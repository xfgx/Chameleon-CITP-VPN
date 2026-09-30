package com.chameleonvpn.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import mobilecore.Mobilecore
import mobilecore.Protector
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

enum class VpnLifecycleState { STOPPED, STARTING, RUNNING, STOPPING, FAILED }

/**
 * Disconnect follows the RU-node client: the tunnel is released immediately on
 * "Отключить" and never waits for a worker that may be sleeping, dialling a
 * replacement CITP session or waiting for the first KS reply. A stale worker
 * notices the generation change and cleans up only what it created itself.
 */
class ChamVpnService:VpnService(){
 companion object {
  const val ACTION_START="com.chameleonvpn.client.START"
  const val ACTION_STOP="com.chameleonvpn.client.STOP"
  private const val CHANNEL="chameleon_vpn"
  private const val NOTIFICATION=41
  @Volatile var lifecycle=VpnLifecycleState.STOPPED;private set
  @Volatile var lastError="";private set
 }
 private var tun:ParcelFileDescriptor?=null
 private val lock=Any()
 private val cleanup=AtomicBoolean(false)
 private val generation=AtomicInteger(0)
 private val coreOwner=AtomicInteger(0)
 @Volatile private var workerThread:Thread?=null

 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int{
  if(intent?.action==ACTION_STOP){stopVpn();return START_NOT_STICKY}
  if(intent?.action!=ACTION_START)return START_NOT_STICKY
  val epoch:Int
  val previous:Thread?
  synchronized(lock){
   if(lifecycle in setOf(VpnLifecycleState.STARTING,VpnLifecycleState.RUNNING,VpnLifecycleState.STOPPING))return START_NOT_STICKY
   cleanup.set(false);lastError="";lifecycle=VpnLifecycleState.STARTING
   epoch=generation.incrementAndGet();previous=workerThread
  }
  AppLog.init(this)
  foreground("Подключаемся…")
  val thread=Thread({run(epoch,previous)},"chameleon-vpn")
  workerThread=thread
  thread.start()
  return START_NOT_STICKY
 }

 private fun current(epoch:Int)=generation.get()==epoch&&!cleanup.get()

 private fun run(epoch:Int,previous:Thread?){
  var own:ParcelFileDescriptor?=null
  var coreStarted=false
  try{
   // A previous worker may still be finishing a network call after a fast disconnect.
   // It must release its own resources before this session touches the shared core.
   if(previous!=null&&previous.isAlive){previous.interrupt();previous.join(20000)}
   if(!current(epoch))return
   val vault=ProfileStore(this);val selected=vault.protocol()
   val profiles=vault.profiles().let{if(selected=="auto")it.sortedBy{p->if(p.mode=="citp")0 else 1} else it.filter{it.mode==selected}}
   require(profiles.isNotEmpty()){ "Для выбранного протокола нет профиля. Обновите доступ или выберите другой протокол." }
   require(vault.entitlementExpiry()>System.currentTimeMillis()/1000){ "Срок ключа истёк. Откройте новый QR." }
   val privateKey=vault.clientKey{Mobilecore.genClientKey()}
   val protector=object:Protector{override fun protect(fd:Int)=this@ChamVpnService.protect(fd)}
   var connected=false
   for(profile in profiles){
    if(!current(epoch))return
    val inner=if(profile.mode=="ks")profile.inner else "10.66.0.2"
    val established=Builder().setSession("Chameleon VPN").setMtu(1300).addAddress(inner,24).addDnsServer("8.8.8.8").allowFamily(OsConstants.AF_INET).addRoute("0.0.0.0",0).setBlocking(true).establish()?:error("Разрешение VPN не выдано")
    // IPv6 is intentionally blocked by VpnService; no allowFamily(AF_INET6).
    synchronized(lock){if(!current(epoch)){established.close();return};tun=established;own=established}
    val fd=ParcelFileDescriptor.dup(established.fileDescriptor).detachFd()
    if(!current(epoch)){ParcelFileDescriptor.adoptFd(fd).close();return}
    coreStarted=true;coreOwner.set(epoch)
    val error=if(profile.mode=="ks")Mobilecore.startKSProfile(profile.addr,profile.ksKey,profile.inner,profile.peerInner,fd,protector) else Mobilecore.start(profile.addr,profile.pubkey,privateKey,fd,protector)
    if(!current(epoch))return
    var ready=error.isEmpty()
    if(ready&&profile.mode=="ks"){val deadline=System.currentTimeMillis()+15000;while(current(epoch)&&Mobilecore.lastRxSec()<0&&System.currentTimeMillis()<deadline)Thread.sleep(100);ready=Mobilecore.lastRxSec()>=0}
    if(!current(epoch))return
    if(ready){connected=true;lifecycle=VpnLifecycleState.RUNNING;notify("Подключено · "+profile.mode.uppercase());break}
    Mobilecore.stop();coreStarted=false
    synchronized(lock){if(tun===established)tun=null};established.close();own=null
    AppLog.d("VPN","profile startup failed: "+profile.mode)
   }
   if(!connected){if(current(epoch))fail("Ни один транспорт не подтвердил подключение. Проверьте сеть и повторите.");return}
   while(current(epoch)){
    if(vault.entitlementExpiry()<=System.currentTimeMillis()/1000){fail("Срок персонального ключа истёк. Получите новый QR.");return}
    val alive=Mobilecore.maintainConnection()
    if(!current(epoch))return
    notify(if(alive)"Подключено · "+Mobilecore.mode().uppercase() else "Восстанавливаем сеанс…")
    Thread.sleep(3000)
   }
  }catch(_:InterruptedException){
  }catch(error:Throwable){
   if(current(epoch))fail(error.message?.take(200)?:"Ошибка подключения")
  }finally{
   // Stale worker: a disconnect already released the tunnel. Only undo a core
   // start that raced with it, and only while no newer session exists.
   if(coreStarted&&!current(epoch)&&coreOwner.get()==epoch){try{Mobilecore.stop()}catch(_:Throwable){}}
   if(generation.get()!=epoch||cleanup.get()){val stale=own;synchronized(lock){if(tun===stale)tun=null};try{stale?.close()}catch(_:Throwable){}}
  }
 }

 private fun fail(message:String){lastError=message;AppLog.e("VPN",message);stopVpn()}

 private fun stopVpn(){
  if(!cleanup.compareAndSet(false,true))return
  val epoch=generation.get()
  lifecycle=VpnLifecycleState.STOPPING
  workerThread?.interrupt()
  Thread({
   // Order matters: the core must release its duplicate TUN fd, otherwise Android keeps
   // the VPN interface up. We do not wait for the worker (dial/sleep) before releasing it.
   try{Mobilecore.stop()}catch(_:Throwable){}
   synchronized(lock){try{tun?.close()}catch(_:Throwable){};tun=null}
   AppLog.i("VPN","туннель отпущен")
   if(generation.get()==epoch){
    try{if(Build.VERSION.SDK_INT>=24)stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION")stopForeground(true)}catch(_:Throwable){}
    getSystemService(NotificationManager::class.java).cancel(NOTIFICATION)
    lifecycle=if(lastError.isEmpty())VpnLifecycleState.STOPPED else VpnLifecycleState.FAILED
    stopSelf()
   }
  },"chameleon-cleanup").start()
 }
 override fun onRevoke(){lastError="Разрешение VPN отозвано";stopVpn();super.onRevoke()}
 override fun onDestroy(){stopVpn();super.onDestroy()}
 private fun notification(text:String):Notification{
  if(Build.VERSION.SDK_INT>=26)getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(CHANNEL,"VPN",NotificationManager.IMPORTANCE_LOW).apply{setShowBadge(false)})
  val open=PendingIntent.getActivity(this,1,Intent(this,MainActivity::class.java),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val stop=PendingIntent.getService(this,2,Intent(this,ChamVpnService::class.java).setAction(ACTION_STOP),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val builder=if(Build.VERSION.SDK_INT>=26)Notification.Builder(this,CHANNEL) else @Suppress("DEPRECATION")Notification.Builder(this)
  return builder.setSmallIcon(R.drawable.ic_chameleon).setContentTitle("Chameleon").setContentText(text).setContentIntent(open).setOngoing(true).setCategory(Notification.CATEGORY_SERVICE).addAction(Notification.Action.Builder(null,"Отключить",stop).build()).build()
 }
 private fun foreground(text:String){if(Build.VERSION.SDK_INT>=34)startForeground(NOTIFICATION,notification(text),ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(NOTIFICATION,notification(text))}
 private fun notify(text:String){if(cleanup.get())return;if(Build.VERSION.SDK_INT<33||checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)==android.content.pm.PackageManager.PERMISSION_GRANTED){getSystemService(NotificationManager::class.java).notify(NOTIFICATION,notification(text))}}
}
