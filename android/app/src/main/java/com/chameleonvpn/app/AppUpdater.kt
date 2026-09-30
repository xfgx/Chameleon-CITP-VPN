package com.chameleonvpn.app

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import org.json.JSONObject
import java.io.File
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/** Release published on the Chameleon website (fixed HTTPS host, verified size, SHA-256 and signer). */
data class AppRelease(val version:String,val file:String,val sha256:String,val size:Long,val status:String)

object AppUpdater {
 private const val MANIFEST=ActivationClient.WEBSITE+"manifest.json"
 private const val DOWNLOAD=ActivationClient.WEBSITE+"download/android"
 private const val MAX_APK=256L*1024*1024
 const val ACTION_INSTALL_STATUS="com.chameleonvpn.client.INSTALL_STATUS"
 @Volatile var installMessage="";internal set

 private fun open(url:String):HttpsURLConnection{
  val connection=URL(url).openConnection() as HttpsURLConnection
  connection.connectTimeout=12000;connection.readTimeout=30000;connection.instanceFollowRedirects=false
  connection.setRequestProperty("Cache-Control","no-cache");connection.useCaches=false
  return connection
 }

 /** Returns the newest published Android release. */
 fun latest():AppRelease{
  val connection=open(MANIFEST)
  try{
   connection.setRequestProperty("Accept","application/json")
   val code=connection.responseCode;if(code!=200)error("Сайт обновлений недоступен (HTTP $code)")
   val text=connection.inputStream.use{stream->val out=java.io.ByteArrayOutputStream();val buffer=ByteArray(8192);while(true){val n=stream.read(buffer);if(n<0)break;require(out.size()+n<=262144){"Ответ слишком большой"};out.write(buffer,0,n)};out.toString("UTF-8")}
   val manifest=JSONObject(text);val appId=manifest.optString("android_app_id")
   require(appId.isEmpty()||appId==BuildConfig.APPLICATION_ID){"Манифест выпущен для другого приложения"}
   val assets=manifest.getJSONArray("assets")
   for(i in 0 until assets.length()){
    val a=assets.getJSONObject(i);if(a.optString("id")!="android")continue
    val sha=a.getString("sha256").lowercase();val size=a.getLong("size");val version=a.getString("version")
    require(Regex("^[0-9a-f]{64}$").matches(sha)&&size in 1..MAX_APK&&Regex("^[0-9]+(\\.[0-9]+){0,3}$").matches(version)){"Некорректная запись о выпуске"}
    return AppRelease(version,a.optString("file"),sha,size,a.optString("status"))
   }
   error("На сайте нет выпуска для Android")
  }finally{connection.disconnect()}
 }

 fun compareVersions(a:String,b:String):Int{
  val x=a.split('.').map{it.toIntOrNull()?:0};val y=b.split('.').map{it.toIntOrNull()?:0}
  for(i in 0 until maxOf(x.size,y.size)){val c=(x.getOrElse(i){0}).compareTo(y.getOrElse(i){0});if(c!=0)return c}
  return 0
 }
 fun isNewer(release:AppRelease)=compareVersions(release.version,BuildConfig.VERSION_NAME)>0

 private fun updateDir(context:Context)=File(context.cacheDir,"updates").apply{mkdirs()}
 fun cleanup(context:Context){try{updateDir(context).listFiles()?.forEach{it.delete()}}catch(_:Throwable){}}

 /** Downloads into private cache, then checks size, SHA-256, package name, version and signer. */
 fun download(context:Context,release:AppRelease,progress:(Long,Long)->Unit,cancelled:()->Boolean):File{
  val dir=updateDir(context);val part=File(dir,"update.apk.part");val done=File(dir,"update-${release.sha256.take(16)}.apk")
  if(done.isFile&&done.length()==release.size&&sha256(done)==release.sha256){verifyPackage(context,done,release);return done}
  dir.listFiles()?.forEach{it.delete()}
  val connection=open(DOWNLOAD)
  try{
   val code=connection.responseCode;if(code!=200)error("Не удалось скачать обновление (HTTP $code)")
   val digest=MessageDigest.getInstance("SHA-256");var total=0L
   connection.inputStream.use{input->part.outputStream().use{output->
    val buffer=ByteArray(65536)
    while(true){
     if(cancelled())error("Загрузка отменена")
     val n=input.read(buffer);if(n<0)break
     total+=n;require(total<=release.size){"Файл больше заявленного размера"}
     digest.update(buffer,0,n);output.write(buffer,0,n);progress(total,release.size)
    }
    output.fd.sync()
   }}
   require(total==release.size){"Загрузка прервана. Повторите попытку."}
   val actual=digest.digest().joinToString(""){"%02x".format(it)}
   require(actual==release.sha256){"Контрольная сумма не совпала. Файл удалён."}
   require(part.renameTo(done)){"Не удалось сохранить обновление"}
  }catch(error:Throwable){part.delete();throw error}finally{connection.disconnect()}
  try{verifyPackage(context,done,release)}catch(error:Throwable){done.delete();throw error}
  return done
 }

 private fun sha256(file:File):String{val d=MessageDigest.getInstance("SHA-256");file.inputStream().use{val b=ByteArray(65536);while(true){val n=it.read(b);if(n<0)break;d.update(b,0,n)}};return d.digest().joinToString(""){"%02x".format(it)}}

 @Suppress("DEPRECATION")
 private fun signers(info:PackageInfo):Set<String>{
  val raw=if(Build.VERSION.SDK_INT>=28){val s=info.signingInfo?:return emptySet();if(s.hasMultipleSigners())s.apkContentsSigners else s.signingCertificateHistory}else info.signatures
  return raw.orEmpty().map{sig->MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString(""){"%02x".format(it)}}.toSet()
 }
 @Suppress("DEPRECATION")
 private fun verifyPackage(context:Context,file:File,release:AppRelease){
  val pm=context.packageManager
  val flags=if(Build.VERSION.SDK_INT>=28)PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
  val archive=pm.getPackageArchiveInfo(file.absolutePath,flags)?:error("Скачанный файл не является приложением Android")
  archive.applicationInfo?.let{it.sourceDir=file.absolutePath;it.publicSourceDir=file.absolutePath}
  require(archive.packageName==context.packageName){"Обновление выпущено для другого приложения"}
  val installed=pm.getPackageInfo(context.packageName,flags)
  val newCode=if(Build.VERSION.SDK_INT>=28)archive.longVersionCode else archive.versionCode.toLong()
  val oldCode=if(Build.VERSION.SDK_INT>=28)installed.longVersionCode else installed.versionCode.toLong()
  require(newCode>oldCode){"Скачанная версия не новее установленной"}
  require(archive.versionName==release.version){"Версия файла не совпадает с сайтом"}
  val mine=signers(installed);val theirs=signers(archive)
  require(mine.isNotEmpty()&&theirs.isNotEmpty()&&theirs.any{it in mine}){"Подпись обновления не совпадает с установленным приложением"}
 }

 /** Android ≥ 8 requires the user to allow installs from this app once. */
 fun canInstall(context:Context)=Build.VERSION.SDK_INT<26||context.packageManager.canRequestPackageInstalls()

 /** Hands the verified APK to the system installer; Android asks the user to confirm. */
 fun install(context:Context,file:File){
  installMessage=""
  val installer=context.packageManager.packageInstaller
  val params=PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply{
   setAppPackageName(context.packageName);setSize(file.length())
   if(Build.VERSION.SDK_INT>=31)setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
   if(Build.VERSION.SDK_INT>=26)setInstallReason(android.content.pm.PackageManager.INSTALL_REASON_USER)
  }
  val id=installer.createSession(params)
  installer.openSession(id).use{session->
   try{
    session.openWrite("chameleon.apk",0,file.length()).use{out->file.inputStream().use{it.copyTo(out,65536)};session.fsync(out)}
    val intent=Intent(context,InstallStatusReceiver::class.java).setAction(ACTION_INSTALL_STATUS).setPackage(context.packageName)
    val flags=PendingIntent.FLAG_UPDATE_CURRENT or (if(Build.VERSION.SDK_INT>=31)PendingIntent.FLAG_MUTABLE else 0)
    session.commit(PendingIntent.getBroadcast(context,id,intent,flags).intentSender)
   }catch(error:Throwable){session.abandon();throw error}
  }
 }
}

/** Receives PackageInstaller status: opens the system confirmation dialog or records the result. */
class InstallStatusReceiver:BroadcastReceiver(){
 override fun onReceive(context:Context,intent:Intent){
  if(intent.action!=AppUpdater.ACTION_INSTALL_STATUS)return
  when(val status=intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE)){
   PackageInstaller.STATUS_PENDING_USER_ACTION->{
    @Suppress("DEPRECATION") val confirm=if(Build.VERSION.SDK_INT>=33)intent.getParcelableExtra(Intent.EXTRA_INTENT,Intent::class.java) else intent.getParcelableExtra(Intent.EXTRA_INTENT)
    if(confirm!=null){AppUpdater.installMessage="Подтвердите установку в системном окне.";confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);try{context.startActivity(confirm)}catch(_:Throwable){AppUpdater.installMessage="Откройте Chameleon и нажмите «Установить» ещё раз."}}
   }
   PackageInstaller.STATUS_SUCCESS->{AppUpdater.installMessage="Обновление установлено.";AppUpdater.cleanup(context)}
   PackageInstaller.STATUS_FAILURE_ABORTED->AppUpdater.installMessage="Установка отменена."
   PackageInstaller.STATUS_FAILURE_CONFLICT,PackageInstaller.STATUS_FAILURE_INCOMPATIBLE->AppUpdater.installMessage="Android отклонил обновление: несовместимая подпись или версия."
   PackageInstaller.STATUS_FAILURE_STORAGE->AppUpdater.installMessage="Недостаточно места для установки."
   else->AppUpdater.installMessage="Установка не выполнена (код $status). "+(intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)?.take(120)?:"")
  }
 }
}
