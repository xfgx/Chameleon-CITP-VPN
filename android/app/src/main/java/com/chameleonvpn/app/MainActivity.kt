package com.chameleonvpn.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.*
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.net.VpnService
import android.os.*
import android.view.*
import android.widget.*
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean

/** Native, content-sized controls. No WebView, analytics or camera. Updates only from the fixed Chameleon site. */
class MainActivity : Activity() {
 private val store by lazy { ProfileStore(this) }
 private val handler=Handler(Looper.getMainLooper())
 private val busy=AtomicBoolean(false)
 private val bg=Color.rgb(17,23,34)
 private val surface=Color.rgb(27,38,54)
 private val muted=Color.rgb(170,183,202)
 private val accent=Color.rgb(33,108,182)
 private val mint=Color.rgb(138,224,188)
 private lateinit var status:TextView
 private lateinit var description:TextView
 private lateinit var power:Button
 private lateinit var traffic:TextView
 private lateinit var accessStatus:TextView
 private lateinit var notice:TextView
 private lateinit var token:EditText
 private lateinit var save:Button
 private lateinit var mark:PowerMark
 private lateinit var body:LinearLayout
 private val pages=mutableMapOf<String,LinearLayout>()
 private val tabs=mutableMapOf<String,Button>()
 private val protocolButtons=mutableMapOf<String,Button>()
 private lateinit var updateStatus:TextView
 private lateinit var updateDetail:TextView
 private lateinit var updateProgress:ProgressBar
 private lateinit var updateButton:Button
 enum class UpdatePhase { IDLE, CHECKING, LATEST, AVAILABLE, DOWNLOADING, READY, ERROR }
 // Process-wide so a download survives rotation or re-opening the screen.
 private companion object {
  @Volatile var updatePhase=UpdatePhase.IDLE
  @Volatile var release:AppRelease?=null
  @Volatile var downloaded:java.io.File?=null
  @Volatile var updateError=""
  @Volatile var downloadedBytes=0L
  @Volatile var lastCheck=0L
 }
 private var page="home"
 private var selected="auto"
 private var hasKey=false
 private var destroyed=false
 private val ticker=object:Runnable {override fun run(){if(!destroyed){render();handler.postDelayed(this,1500)}}}
 private fun dp(n:Int)=(n*resources.displayMetrics.density+0.5f).toInt()
 private fun shape(color:Int)=GradientDrawable().apply{setColor(color);cornerRadius=dp(12).toFloat()}
 private fun label(value:String,size:Float=16f,bold:Boolean=false)=TextView(this).apply{
  text=value;textSize=size;setTextColor(if(bold)Color.WHITE else muted);setPadding(0,dp(4),0,dp(4));setLineSpacing(dp(3).toFloat(),1.05f)
  if(bold)setTypeface(typeface,Typeface.BOLD)
 }
 private fun button(value:String,primary:Boolean=false,action:()->Unit)=Button(this).apply{
  text=value;textSize=16f;isAllCaps=false;minHeight=dp(56);minimumHeight=dp(56);setPadding(dp(16),dp(16),dp(16),dp(16));setTextColor(Color.WHITE)
  background=shape(if(primary)accent else Color.rgb(35,50,71));stateListAnimator=null;setOnClickListener{action()}
 }
 private fun column()=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
 private fun LinearLayout.add(view:View,gap:Int=12){addView(view,LinearLayout.LayoutParams(-1,-2).apply{topMargin=dp(gap)})}
 private fun card()=column().apply{background=shape(surface);setPadding(dp(20),dp(20),dp(20),dp(20))}
 private fun setLabel(view:TextView,value:String){if(view.text.toString()!=value)view.text=value}
 override fun onCreate(savedInstanceState:Bundle?){
  super.onCreate(savedInstanceState);AppLog.init(this);selected=store.protocol();hasKey=store.activationToken().isNotEmpty()
  window.statusBarColor=bg;window.navigationBarColor=bg
  val root=column().apply{setBackgroundColor(bg);fitsSystemWindows=true}
  val heading=column().apply{setPadding(dp(20),dp(16),dp(20),dp(12))}
  heading.add(label("Chameleon",25f,true),0);heading.add(label("Персональный VPN · v${BuildConfig.VERSION_NAME}",14f),2);root.add(heading,0)
  // Two rows of two equal tabs: every label fits at any system font size, no baseline shift.
  val navigation=column().apply{setPadding(dp(16),0,dp(16),dp(8))}
  val titles=listOf("home" to "VPN","protocol" to "Протокол","access" to "Доступ","update" to "Обновления")
  for(rowItems in titles.chunked(2)){
   val row=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL;isBaselineAligned=false}
   for((id,title) in rowItems){
    val tab=button(title){showPage(id)}.apply{textSize=15f;maxLines=1;ellipsize=null;gravity=Gravity.CENTER;minHeight=dp(48);minimumHeight=dp(48);setPadding(dp(8),dp(10),dp(8),dp(10));contentDescription="Раздел: $title"}
    tabs[id]=tab;row.addView(tab,LinearLayout.LayoutParams(0,dp(48),1f).apply{marginStart=dp(4);marginEnd=dp(4)})
   }
   navigation.addView(row,LinearLayout.LayoutParams(-1,-2).apply{topMargin=dp(if(navigation.childCount==0)0 else 8)})
  }
  root.add(navigation,0)
  val scroll=ScrollView(this).apply{isFillViewport=true;clipToPadding=false}
  body=column().apply{setPadding(dp(20),dp(8),dp(20),dp(24))};scroll.addView(body,FrameLayout.LayoutParams(-1,-2));root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
  buildHome();buildProtocol();buildAccess();buildUpdate()
  notice=label("",14f).apply{setTextColor(mint);accessibilityLiveRegion=View.ACCESSIBILITY_LIVE_REGION_POLITE};body.add(notice,16)
  body.add(label("Без рекламы и аналитики. Содержимое трафика не записывается.",14f),16)
  body.add(button("Инструкции и исходники"){openWebsite()},12)
  setContentView(root);showPage(savedInstanceState?.getString("page")?:"home");acceptIntent(intent);render()
  if(page!="update")checkUpdate(quiet=true)
 }
 private fun buildHome(){
  val home=column();pages["home"]=home;body.add(home,0)
  home.add(label("Ваше подключение",23f,true),4)
  val connection=card();home.add(connection,16)
  mark=PowerMark(this);connection.addView(mark,LinearLayout.LayoutParams(dp(80),dp(80)).apply{gravity=Gravity.CENTER_HORIZONTAL;bottomMargin=dp(12)})
  status=label("Отключено",25f,true).apply{gravity=Gravity.CENTER;accessibilityLiveRegion=View.ACCESSIBILITY_LIVE_REGION_POLITE};connection.add(status,0)
  description=label("Одна кнопка. Сервер выбирается автоматически.").apply{gravity=Gravity.CENTER};connection.add(description,8)
  power=button("Подключить VPN",true){toggle()};connection.add(power,24)
  val metrics=card();home.add(metrics,16);metrics.add(label("ТРАФИК СЕАНСА",14f),0);traffic=label("↑ 0 Б   ↓ 0 Б",20f,true);metrics.add(traffic,8)
 }
 private fun buildProtocol(){
  val section=column();pages["protocol"]=section;body.add(section,0)
  section.add(label("Протокол VPN",23f,true),4);section.add(label("Выбор сохраняется. Для смены протокола отключите VPN."),8)
  for((mode,detail) in listOf("auto" to "Рекомендуется: сначала CITP, затем KS при недоступности. Сохраняет прежний автовыбор Android.","citp" to "Защищённый мультиплексированный транспорт. Рекомендуется по умолчанию.","ks" to "KS через UDP. Нужны персональный KS-профиль и доступность UDP в вашей сети.")){
   val item=card();section.add(item,16);item.add(label(modeName(mode),21f,true),0);item.add(label(detail),8)
   val choose=button("Выбрать ${modeName(mode)}"){if(!active()&&!busy.get()){store.setProtocol(mode);selected=mode;setLabel(notice,"Выбран ${modeName(mode)} для следующего подключения.");render()}}
   protocolButtons[mode]=choose;item.add(choose,20)
  }
  section.add(label("При ручном выборе приложение не переключается на другой протокол незаметно.",14f),16)
 }
 private fun buildAccess(){
  val section=column();pages["access"]=section;body.add(section,0);section.add(label("Персональный доступ",23f,true),4)
  val item=card();section.add(item,16);accessStatus=label("");item.add(accessStatus,0)
  token=EditText(this).apply{hint="Ключ или QR-ссылка";textSize=16f;setTextColor(Color.WHITE);setHintTextColor(muted);setSingleLine(true);inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD;setPadding(dp(16),dp(16),dp(16),dp(16));minHeight=dp(56);background=shape(bg);if(Build.VERSION.SDK_INT>=26)importantForAutofill=View.IMPORTANT_FOR_AUTOFILL_NO;contentDescription="Персональный ключ или QR-ссылка"};item.add(token,16)
  save=button("Сохранить ключ",true){saveToken(token.text.toString())};item.add(save,16)
  item.add(button("Получить QR в боте"){openWebsite("#activation")},12)
  section.add(label("Ключ хранится зашифрованным с помощью Android Keystore. Адреса серверов и порты вводить не нужно.",14f),16)
 }
 private fun buildUpdate(){
  val section=column();pages["update"]=section;body.add(section,0);section.add(label("Обновление приложения",23f,true),4)
  val item=card();section.add(item,16)
  item.add(label("Установлена версия ${BuildConfig.VERSION_NAME}",14f),0)
  updateStatus=label("Проверяем обновления…",21f,true).apply{accessibilityLiveRegion=View.ACCESSIBILITY_LIVE_REGION_POLITE};item.add(updateStatus,8)
  updateDetail=label("");item.add(updateDetail,4)
  updateProgress=ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal).apply{max=1000;visibility=View.GONE};item.add(updateProgress,12)
  updateButton=button("Проверить обновления",true){updateAction()};item.add(updateButton,16)
  section.add(label("Проверка выполняется при открытии этой вкладки. Файл скачивается только с сайта Chameleon, проверяется по SHA-256 и подписи разработчика, затем Android просит подтвердить установку.",14f),16)
 }
 private fun checkUpdate(quiet:Boolean=false){
  if(updatePhase==UpdatePhase.CHECKING||updatePhase==UpdatePhase.DOWNLOADING)return
  if(quiet&&System.currentTimeMillis()-lastCheck<30000)return
  if(!quiet){updatePhase=UpdatePhase.CHECKING;renderUpdate()}
  lastCheck=System.currentTimeMillis()
  Thread({try{val latest=AppUpdater.latest();handler.post{if(destroyed)return@post;release=latest
     if(AppUpdater.isNewer(latest)){if(updatePhase!=UpdatePhase.READY||downloaded==null)updatePhase=UpdatePhase.AVAILABLE}else{updatePhase=UpdatePhase.LATEST;downloaded=null;AppUpdater.cleanup(this)}
     renderUpdate()}}
   catch(error:Exception){handler.post{if(destroyed)return@post;if(!quiet){updateError=error.message?.take(160)?:"Нет связи с сайтом обновлений";updatePhase=UpdatePhase.ERROR};renderUpdate()}}},"chameleon-update-check").start()
 }
 private fun updateAction(){
  when(updatePhase){
   UpdatePhase.AVAILABLE->startDownload()
   UpdatePhase.READY->installUpdate()
   UpdatePhase.CHECKING,UpdatePhase.DOWNLOADING->{}
   else->checkUpdate()
  }
 }
 private fun startDownload(){
  val target=release?:return;updatePhase=UpdatePhase.DOWNLOADING;downloadedBytes=0;renderUpdate()
  Thread({try{val file=AppUpdater.download(applicationContext,target,{done,_->downloadedBytes=done},{false});downloaded=file;updatePhase=UpdatePhase.READY;handler.post{if(destroyed)return@post;renderUpdate();installUpdate()}}
   catch(error:Exception){updateError=error.message?.take(160)?:"Не удалось скачать обновление";updatePhase=UpdatePhase.ERROR;handler.post{if(!destroyed)renderUpdate()}}},"chameleon-update-download").start()
 }
 private fun installUpdate(){
  val file=downloaded?:run{updatePhase=UpdatePhase.AVAILABLE;renderUpdate();return}
  if(!file.isFile){downloaded=null;updatePhase=UpdatePhase.AVAILABLE;renderUpdate();return}
  if(!AppUpdater.canInstall(this)){
   setLabel(notice,"Разрешите Chameleon устанавливать приложения, затем вернитесь и нажмите «Установить».")
   try{startActivity(Intent(android.provider.Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,Uri.parse("package:$packageName")))}catch(_:Exception){}
   return
  }
  // The running VPN would be killed by the package replacement; release the tunnel cleanly first.
  if(active())startService(Intent(this,ChamVpnService::class.java).setAction(ChamVpnService.ACTION_STOP))
  try{AppUpdater.install(this,file);setLabel(notice,"Подтвердите установку в системном окне Android.")}
  catch(error:Exception){updateError=error.message?.take(160)?:"Установщик Android недоступен";updatePhase=UpdatePhase.ERROR;renderUpdate()}
 }
 private fun renderUpdate(){
  if(!::updateStatus.isInitialized)return
  val r=release
  val size=r?.let{" · %.1f МиБ".format(it.size/1048576.0)}?:""
  setLabel(updateStatus,when(updatePhase){UpdatePhase.IDLE->"Проверка обновлений";UpdatePhase.CHECKING->"Проверяем обновления…";UpdatePhase.LATEST->"Установлена последняя версия";UpdatePhase.AVAILABLE->"Доступна версия ${r?.version}";UpdatePhase.DOWNLOADING->"Скачиваем ${r?.version}…";UpdatePhase.READY->"Версия ${r?.version} готова к установке";UpdatePhase.ERROR->"Не удалось проверить обновление"})
  setLabel(updateDetail,when(updatePhase){UpdatePhase.LATEST->"На сайте опубликована версия ${r?.version}. Обновление не требуется.";UpdatePhase.AVAILABLE->"Новая версия${size}${if(r?.status=="beta")" · beta" else ""}. Нажмите «Обновить», чтобы скачать и установить.";UpdatePhase.DOWNLOADING->"${downloadedBytes/1048576} из ${(r?.size?:0)/1048576} МиБ";UpdatePhase.READY->AppUpdater.installMessage.ifEmpty{"Файл проверен: размер, SHA-256 и подпись совпадают."};UpdatePhase.ERROR->updateError;else->""})
  updateProgress.visibility=if(updatePhase==UpdatePhase.DOWNLOADING)View.VISIBLE else View.GONE
  if(updatePhase==UpdatePhase.DOWNLOADING&&r!=null&&r.size>0)updateProgress.progress=(downloadedBytes*1000/r.size).toInt()
  setLabel(updateButton,when(updatePhase){UpdatePhase.AVAILABLE->"Обновить";UpdatePhase.READY->"Установить";UpdatePhase.CHECKING->"Проверяем…";UpdatePhase.DOWNLOADING->"Скачиваем…";UpdatePhase.ERROR->"Повторить";else->"Проверить ещё раз"})
  updateButton.isEnabled=updatePhase!=UpdatePhase.CHECKING&&updatePhase!=UpdatePhase.DOWNLOADING;updateButton.alpha=if(updateButton.isEnabled)1f else .55f
  tabs["update"]?.let{setLabel(it,if(updatePhase==UpdatePhase.AVAILABLE||updatePhase==UpdatePhase.READY)"Обновления •" else "Обновления")}
 }
 private fun showPage(id:String){page=if(id in pages)id else "home";for((key,view) in pages)view.visibility=if(key==page)View.VISIBLE else View.GONE;for((key,tab) in tabs)tab.background=shape(if(key==page)accent else Color.rgb(23,31,44));if(::notice.isInitialized)setLabel(notice,"");if(page=="update")checkUpdate()}
 private fun modeName(mode:String)=if(mode=="auto")"Автовыбор" else mode.uppercase()
 private fun active()=ChamVpnService.lifecycle in setOf(VpnLifecycleState.STARTING,VpnLifecycleState.RUNNING,VpnLifecycleState.STOPPING)
 override fun onNewIntent(intent:Intent){super.onNewIntent(intent);setIntent(intent);acceptIntent(intent)}
 private fun linkToken(value:String):String {val trimmed=value.trim();if(!trimmed.startsWith("https://"))return trimmed;val uri=Uri.parse(trimmed);require(uri.scheme=="https"&&uri.host=="vpn.example.com"&&uri.port==-1&&uri.path=="/vpn/activate"){"Неверная QR-ссылка"};return uri.fragment.orEmpty().removePrefix("token=")}
 private fun acceptIntent(intent:Intent?){val uri=intent?.data?:return;intent.data=null;if(uri.scheme!="https"||uri.host!="vpn.example.com"||uri.port!=-1||uri.path!="/vpn/activate")return;if(active()){setLabel(notice,"Сначала отключите VPN и повторно откройте QR.");return};AlertDialog.Builder(this).setTitle("Персональный доступ").setMessage("Сохранить ключ и привязать его к этой установке?").setNegativeButton("Отмена",null).setPositiveButton("Активировать"){_,_->saveToken(uri.toString())}.show()}
 private fun saveToken(value:String){if(active()||busy.get())return;try{store.setActivationToken(linkToken(value));hasKey=true;token.text.clear();setLabel(notice,"Ключ сохранён. Откройте VPN и подключитесь.");notice.setTextColor(mint);render()}catch(_:Exception){notice.setTextColor(Color.rgb(255,172,166));setLabel(notice,"Неверный формат ключа. Вставьте ключ или QR-ссылку из бота.")}}
 private fun openWebsite(suffix:String=""){try{startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(ActivationClient.WEBSITE+suffix)))}catch(_:Exception){setLabel(notice,"Откройте сайт Chameleon в браузере.")}}
 private fun toggle(){if(active()){startService(Intent(this,ChamVpnService::class.java).setAction(ChamVpnService.ACTION_STOP));return};if(busy.get())return;if(!hasKey){showPage("access");return};busy.set(true);setLabel(notice,"");render();Thread({try{ActivationClient.refresh(store);handler.post{if(!destroyed){val permission=VpnService.prepare(this);if(permission==null)startVpn() else @Suppress("DEPRECATION")startActivityForResult(permission,100)}}}catch(error:Exception){handler.post{if(!destroyed){notice.setTextColor(Color.rgb(255,172,166));setLabel(notice,error.message?:"Сервис недоступен. Повторите попытку.")}}}finally{handler.post{busy.set(false);if(!destroyed)render()}}},"chameleon-activation").start()}
 @Deprecated("Android permission bridge")override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?){super.onActivityResult(requestCode,resultCode,data);if(requestCode==100){if(resultCode==RESULT_OK)startVpn() else setLabel(notice,"Разрешение VPN не выдано.")}}
 private fun startVpn(){if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED){val prefs=getSharedPreferences("permission",MODE_PRIVATE);if(!prefs.getBoolean("notification_asked",false)){prefs.edit().putBoolean("notification_asked",true).apply();requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),200)}};ContextCompat.startForegroundService(this,Intent(this,ChamVpnService::class.java).setAction(ChamVpnService.ACTION_START));render()}
 private fun render(){
  if(page=="update"||updatePhase==UpdatePhase.DOWNLOADING)renderUpdate()
  val phase=ChamVpnService.lifecycle;val connected=phase==VpnLifecycleState.RUNNING&&mobilecore.Mobilecore.connectionStatus()=="connected"
  setLabel(status,when{busy.get()->"Проверяем доступ…";phase==VpnLifecycleState.STARTING->"Подключаемся…";phase==VpnLifecycleState.STOPPING->"Отключаемся…";connected->"Соединение защищено";phase==VpnLifecycleState.RUNNING->"Восстанавливаем связь";ChamVpnService.lastError.isNotEmpty()->"Ошибка подключения";else->"Готов к подключению"})
  setLabel(description,when{connected->"VPN подключён · ${mobilecore.Mobilecore.mode().uppercase()}";phase==VpnLifecycleState.RUNNING->"Туннель остаётся поднят. Восстанавливаем сеанс.";ChamVpnService.lastError.isNotEmpty()->ChamVpnService.lastError;busy.get()||phase==VpnLifecycleState.STARTING->"Проверяем доступ и устанавливаем соединение.";!hasKey->"Сначала получите персональный QR-код в боте.";else->"Выбран ${modeName(selected)}. Ваш трафик пока не защищён VPN."})
  setLabel(power,if(active())"Отключить VPN" else if(hasKey)"Подключить VPN" else "Активировать доступ");power.isEnabled=!busy.get()&&phase!=VpnLifecycleState.STOPPING;power.alpha=if(power.isEnabled)1f else .55f
  setLabel(traffic,if(connected)"↑ ${formatBytes(mobilecore.Mobilecore.upBytes())}   ↓ ${formatBytes(mobilecore.Mobilecore.downBytes())}" else "↑ 0 Б   ↓ 0 Б")
  setLabel(accessStatus,if(hasKey)"Ключ сохранён. Он проверяется при подключении." else "Вставьте персональный ключ или QR-ссылку из бота.")
  save.isEnabled=!active()&&!busy.get();save.alpha=if(save.isEnabled)1f else .55f;token.isEnabled=save.isEnabled
  for((mode,b) in protocolButtons){setLabel(b,if(mode==selected)"Выбран ${modeName(mode)}" else "Выбрать ${modeName(mode)}");if(b.tag!=(mode==selected)){b.background=shape(if(mode==selected)accent else Color.rgb(35,50,71));b.tag=(mode==selected)};b.isEnabled=!active()&&!busy.get();b.alpha=if(b.isEnabled)1f else .55f}
  val color=if(connected)mint else if(ChamVpnService.lastError.isNotEmpty())Color.rgb(255,172,166) else Color.rgb(143,191,247);if(mark.tint!=color){mark.tint=color;mark.invalidate()}
 }
 private fun formatBytes(n:Long):String=if(n<1048576)"${n/1024} КиБ" else "%.1f МиБ".format(n/1048576.0)
 override fun onResume(){super.onResume();handler.removeCallbacks(ticker);handler.post(ticker);renderUpdate()}
 override fun onPause(){handler.removeCallbacks(ticker);super.onPause()}
 override fun onSaveInstanceState(out:Bundle){out.putString("page",page);super.onSaveInstanceState(out)}
 override fun onDestroy(){destroyed=true;handler.removeCallbacksAndMessages(null);super.onDestroy()}
 private class PowerMark(context:android.content.Context):View(context){var tint=Color.rgb(143,191,247);private val pen=Paint(Paint.ANTI_ALIAS_FLAG);override fun onDraw(c:Canvas){super.onDraw(c);val scale=minOf(width,height)/80f;c.save();c.scale(scale,scale);pen.style=Paint.Style.FILL;pen.color=Color.rgb(37,59,83);c.drawCircle(40f,40f,40f,pen);pen.style=Paint.Style.STROKE;pen.strokeWidth=3f;pen.strokeCap=Paint.Cap.ROUND;pen.color=tint;c.drawArc(RectF(21f,21f,59f,59f),-50f,280f,false,pen);c.drawLine(40f,18f,40f,40f,pen);c.restore()}}
}
