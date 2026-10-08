package com.chameleonvpn.app

import android.animation.ArgbEvaluator
import android.animation.LayoutTransition
import android.animation.ValueAnimator
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.*
import android.content.res.ColorStateList
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.view.animation.DecelerateInterpolator
import android.view.animation.LinearInterpolator
import android.view.animation.OvershootInterpolator
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
 private lateinit var scroll:ScrollView
 private lateinit var heading:LinearLayout
 private lateinit var navigation:LinearLayout
 private var stopRequestedAt=0L
 private var startRequestedAt=0L
 private var requestPhase=VpnLifecycleState.STOPPED
 private val pages=mutableMapOf<String,LinearLayout>()
 private val tabs=mutableMapOf<String,Button>()
 private val protocolButtons=mutableMapOf<String,Button>()
 private lateinit var ruDirectButton:Button
 private var ruDirect=true
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
 // Adaptive refresh: 250 мс while something is changing, 1 с otherwise.
 private val ticker=object:Runnable {override fun run(){if(!destroyed){render();handler.postDelayed(this,if(transitional())250 else 1000)}}}
 private fun kick(){handler.removeCallbacks(ticker);handler.postDelayed(ticker,60)}
 private fun transitional():Boolean{val p=ChamVpnService.lifecycle;return busy.get()||p==VpnLifecycleState.STARTING||p==VpnLifecycleState.STOPPING||pendingStop()||pendingStart()||updatePhase==UpdatePhase.DOWNLOADING||updatePhase==UpdatePhase.CHECKING}
 // Optimistic UI: the tap is reflected at once, before the service reports its new state.
 private fun pendingStop()=stopRequestedAt>0&&SystemClock.uptimeMillis()-stopRequestedAt<3000&&ChamVpnService.lifecycle==requestPhase&&ChamVpnService.lifecycle!=VpnLifecycleState.STOPPED
 private fun pendingStart()=startRequestedAt>0&&SystemClock.uptimeMillis()-startRequestedAt<3000&&ChamVpnService.lifecycle==requestPhase
 private fun dp(n:Int)=(n*resources.displayMetrics.density+0.5f).toInt()
 private fun shape(color:Int)=GradientDrawable().apply{setColor(color);cornerRadius=dp(12).toFloat()}
 private fun label(value:String,size:Float=16f,bold:Boolean=false)=TextView(this).apply{
  text=value;textSize=size;setTextColor(if(bold)Color.WHITE else muted);setPadding(0,dp(4),0,dp(4));setLineSpacing(dp(3).toFloat(),1.05f)
  if(bold)setTypeface(typeface,Typeface.BOLD)
 }
 // ---- Motion: every tap answers within one frame (ripple + press scale + haptic), state
 // changes cross-fade, colours blend, pages slide in. All of it honours the system
 // "animation scale" setting (0 = no animation) and runs on the render thread where possible.
 private val ease=DecelerateInterpolator(1.8f)
 private val springBack=OvershootInterpolator(2.2f)
 private val argb=ArgbEvaluator()
 private fun motion()=Build.VERSION.SDK_INT<26||ValueAnimator.areAnimatorsEnabled()
 private val fills=HashMap<View,Int>()
 private val fillAnimators=HashMap<View,ValueAnimator>()
 private val alphaTargets=HashMap<View,Float>()
 private val textTargets=HashMap<TextView,String>()
 private fun pressable(color:Int)=RippleDrawable(ColorStateList.valueOf(Color.argb(56,255,255,255)),shape(color),shape(Color.WHITE))
 private fun fillOf(view:View)=(view.background as? RippleDrawable)?.getDrawable(0) as? GradientDrawable
 /** Blends a button's fill colour instead of swapping the drawable (no flash, ripple kept). */
 private fun setFill(view:View,color:Int,animate:Boolean=true){
  val from=fills[view]?:color;if(from==color&&fills.containsKey(view))return
  fills[view]=color;fillAnimators.remove(view)?.cancel()
  val fill=fillOf(view)?:run{view.background=pressable(color);return}
  if(!animate||!motion()||from==color){fill.setColor(color);return}
  fillAnimators[view]=ValueAnimator.ofObject(argb,from,color).apply{duration=220;interpolator=ease;addUpdateListener{fill.setColor(it.animatedValue as Int)};start()}
 }
 /** Enabled/disabled fades instead of snapping; no-op when nothing changes (ticker-safe). */
 private fun setActive(view:View,enabled:Boolean){
  view.isEnabled=enabled;val target=if(enabled)1f else .5f
  if(alphaTargets[view]==target)return;alphaTargets[view]=target
  if(motion())view.animate().alpha(target).setDuration(200).setInterpolator(ease).start() else view.alpha=target
 }
 @android.annotation.SuppressLint("ClickableViewAccessibility")
 private fun pressFeedback(view:View){
  view.setOnTouchListener{v,e->
   when(e.actionMasked){
    MotionEvent.ACTION_DOWN->if(v.isEnabled)v.animate().scaleX(.965f).scaleY(.965f).setDuration(80).setInterpolator(ease).start()
    MotionEvent.ACTION_UP,MotionEvent.ACTION_CANCEL->v.animate().scaleX(1f).scaleY(1f).setDuration(220).setInterpolator(springBack).start()
   }
   false
  }
 }
 private fun haptic(view:View,strong:Boolean=false){
  val kind=if(strong&&Build.VERSION.SDK_INT>=30)HapticFeedbackConstants.CONFIRM else if(strong)HapticFeedbackConstants.VIRTUAL_KEY else HapticFeedbackConstants.CLOCK_TICK
  view.performHapticFeedback(kind)
 }
 /** Cross-fades a status line: old text slides up and fades, new text rises in. */
 private fun setLabelSmooth(view:TextView,value:String){
  if(textTargets[view]==value)return
  val first=!textTargets.containsKey(view);textTargets[view]=value
  if(first||!motion()||!view.isShown){view.animate().cancel();view.text=value;view.alpha=1f;view.translationY=0f;return}
  view.animate().cancel()
  view.animate().alpha(0f).translationY(-dp(6).toFloat()).setDuration(110).setInterpolator(ease).withEndAction{
   view.text=value;view.translationY=dp(8).toFloat()
   view.animate().alpha(1f).translationY(0f).setDuration(200).setInterpolator(ease).start()
  }.start()
 }
 private fun enter(view:View,delay:Long,dx:Float=0f,dy:Float=dp(14).toFloat()){
  if(!motion())return
  view.alpha=0f;view.translationX=dx;view.translationY=dy
  view.animate().alpha(1f).translationX(0f).translationY(0f).setStartDelay(delay).setDuration(280).setInterpolator(ease).withLayer().start()
 }
 private fun button(value:String,primary:Boolean=false,strong:Boolean=primary,action:()->Unit)=Button(this).apply{
  text=value;textSize=16f;isAllCaps=false;minHeight=dp(56);minimumHeight=dp(56);setPadding(dp(16),dp(16),dp(16),dp(16));setTextColor(Color.WHITE)
  val color=if(primary)accent else Color.rgb(35,50,71);background=pressable(color);fills[this]=color;stateListAnimator=null
  pressFeedback(this);setOnClickListener{haptic(it,strong);action()}
 }
 private fun column()=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
 private fun LinearLayout.add(view:View,gap:Int=12){addView(view,LinearLayout.LayoutParams(-1,-2).apply{topMargin=dp(gap)})}
 private fun card()=column().apply{background=shape(surface);setPadding(dp(20),dp(20),dp(20),dp(20));layoutTransition=smoothLayout()}
 private fun smoothLayout()=LayoutTransition().apply{enableTransitionType(LayoutTransition.CHANGING);setDuration(200);setInterpolator(LayoutTransition.CHANGING,ease)}
 private fun setLabel(view:TextView,value:String){if(view.text.toString()!=value)view.text=value}
 override fun onCreate(savedInstanceState:Bundle?){
  super.onCreate(savedInstanceState);AppLog.init(this);selected=store.protocol();ruDirect=store.ruDirect();hasKey=store.activationToken().isNotEmpty()
  window.statusBarColor=bg;window.navigationBarColor=bg
  val root=column().apply{setBackgroundColor(bg);fitsSystemWindows=true}
  heading=column().apply{setPadding(dp(20),dp(16),dp(20),dp(12))}
  heading.add(label("Chameleon",25f,true),0);heading.add(label("Персональный VPN · v${AppUpdater.installedVersion(this)}",14f),2);root.add(heading,0)
  // Two rows of two equal tabs: every label fits at any system font size, no baseline shift.
  navigation=column().apply{setPadding(dp(16),0,dp(16),dp(8))}
  val titles=listOf("home" to "VPN","protocol" to "Протокол","access" to "Доступ","update" to "Обновления")
  for(rowItems in titles.chunked(2)){
   val row=LinearLayout(this).apply{orientation=LinearLayout.HORIZONTAL;isBaselineAligned=false}
   for((id,title) in rowItems){
    val tab=button(title,strong=false){showPage(id)}.apply{textSize=15f;maxLines=1;ellipsize=null;gravity=Gravity.CENTER;minHeight=dp(48);minimumHeight=dp(48);setPadding(dp(8),dp(10),dp(8),dp(10));contentDescription="Раздел: $title"}
    tabs[id]=tab;row.addView(tab,LinearLayout.LayoutParams(0,dp(48),1f).apply{marginStart=dp(4);marginEnd=dp(4)})
   }
   navigation.addView(row,LinearLayout.LayoutParams(-1,-2).apply{topMargin=dp(if(navigation.childCount==0)0 else 8)})
  }
  root.add(navigation,0)
  scroll=ScrollView(this).apply{isFillViewport=true;clipToPadding=false;isVerticalScrollBarEnabled=false;overScrollMode=View.OVER_SCROLL_IF_CONTENT_SCROLLS}
  body=column().apply{setPadding(dp(20),dp(8),dp(20),dp(24))};scroll.addView(body,FrameLayout.LayoutParams(-1,-2));root.addView(scroll,LinearLayout.LayoutParams(-1,0,1f))
  buildHome();buildProtocol();buildAccess();buildUpdate()
  notice=label("",14f).apply{setTextColor(mint);accessibilityLiveRegion=View.ACCESSIBILITY_LIVE_REGION_POLITE};body.add(notice,16)
  body.add(label("Без рекламы и аналитики. Содержимое трафика не записывается.",14f),16)
  body.add(button("Инструкции и исходники"){openWebsite()},12)
  setContentView(root);showPage(savedInstanceState?.getString("page")?:"home",animate=false);acceptIntent(intent);render()
  if(savedInstanceState==null){enter(heading,0);enter(navigation,50);pages[page]?.let{p->for(i in 0 until p.childCount)enter(p.getChildAt(i),100L+45L*i)}}
  if(page!="update")checkUpdate(quiet=true)
 }
 private fun buildHome(){
  val home=column();pages["home"]=home;body.add(home,0)
  home.add(label("Ваше подключение",23f,true),4)
  val connection=card();home.add(connection,16)
  mark=PowerMark(this).apply{isClickable=true;contentDescription="Подключить или отключить VPN";setOnClickListener{if(power.isEnabled){haptic(it,true);it.animate().scaleX(.9f).scaleY(.9f).setDuration(90).setInterpolator(ease).withEndAction{it.animate().scaleX(1f).scaleY(1f).setDuration(260).setInterpolator(springBack).start()}.start();toggle()}}}
  connection.addView(mark,LinearLayout.LayoutParams(dp(112),dp(112)).apply{gravity=Gravity.CENTER_HORIZONTAL;bottomMargin=dp(4)})
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
  val split=card();section.add(split,24);split.add(label("Российские сайты напрямую",21f,true),0)
  split.add(label("Сайты и сервисы РФ (Госуслуги, банки, Яндекс, VK, маркетплейсы) открываются напрямую с вашего адреса, без VPN. Остальной трафик, включая зарубежные сервисы, идёт через VPN как обычно."),8)
  ruDirectButton=button("Включено"){if(!active()&&!busy.get()){ruDirect=!ruDirect;store.setRuDirect(ruDirect);setLabel(notice,if(ruDirect)"Российские сайты пойдут напрямую со следующего подключения." else "Весь трафик пойдёт через VPN со следующего подключения.");render()}}
  split.add(ruDirectButton,20)
  if(Build.VERSION.SDK_INT<33)split.add(label("На Android до 13 напрямую идут крупные российские сети; небольшие сайты могут открываться через VPN.",14f),12)
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
  item.add(label("Установлена версия ${AppUpdater.installedVersion(this)}",14f),0)
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
     if(AppUpdater.isNewer(this,latest)){if(updatePhase!=UpdatePhase.READY||downloaded==null)updatePhase=UpdatePhase.AVAILABLE}else{updatePhase=UpdatePhase.LATEST;downloaded=null;AppUpdater.cleanup(this)}
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
  setLabelSmooth(updateStatus,when(updatePhase){UpdatePhase.IDLE->"Проверка обновлений";UpdatePhase.CHECKING->"Проверяем обновления…";UpdatePhase.LATEST->"Установлена последняя версия";UpdatePhase.AVAILABLE->"Доступна версия ${r?.version}";UpdatePhase.DOWNLOADING->"Скачиваем ${r?.version}…";UpdatePhase.READY->"Версия ${r?.version} готова к установке";UpdatePhase.ERROR->"Не удалось проверить обновление"})
  setLabel(updateDetail,when(updatePhase){UpdatePhase.LATEST->"На сайте опубликована версия ${r?.version}. Обновление не требуется.";UpdatePhase.AVAILABLE->"Новая версия${size}${if(r?.status=="beta")" · beta" else ""}. Нажмите «Обновить», чтобы скачать и установить.";UpdatePhase.DOWNLOADING->"${downloadedBytes/1048576} из ${(r?.size?:0)/1048576} МиБ";UpdatePhase.READY->AppUpdater.installMessage.ifEmpty{"Файл проверен: размер, SHA-256 и подпись совпадают."};UpdatePhase.ERROR->updateError;else->""})
  val showBar=if(updatePhase==UpdatePhase.DOWNLOADING)View.VISIBLE else View.GONE;if(updateProgress.visibility!=showBar)updateProgress.visibility=showBar
  if(updatePhase==UpdatePhase.DOWNLOADING&&r!=null&&r.size>0){val p=(downloadedBytes*1000/r.size).toInt();if(Build.VERSION.SDK_INT>=24)updateProgress.setProgress(p,true) else updateProgress.progress=p}
  setLabel(updateButton,when(updatePhase){UpdatePhase.AVAILABLE->"Обновить";UpdatePhase.READY->"Установить";UpdatePhase.CHECKING->"Проверяем…";UpdatePhase.DOWNLOADING->"Скачиваем…";UpdatePhase.ERROR->"Повторить";else->"Проверить ещё раз"})
  setActive(updateButton,updatePhase!=UpdatePhase.CHECKING&&updatePhase!=UpdatePhase.DOWNLOADING)
  tabs["update"]?.let{setLabel(it,if(updatePhase==UpdatePhase.AVAILABLE||updatePhase==UpdatePhase.READY)"Обновления •" else "Обновления")}
 }
 private val order=listOf("home","protocol","access","update")
 private fun showPage(id:String,animate:Boolean=true){
  val previous=page;page=if(id in pages)id else "home";val changed=previous!=page||!animate
  for((key,view) in pages){val v=if(key==page)View.VISIBLE else View.GONE;if(view.visibility!=v)view.visibility=v}
  for((key,tab) in tabs)setFill(tab,if(key==page)accent else Color.rgb(23,31,44),animate)
  if(::notice.isInitialized&&changed)setLabel(notice,"")
  if(animate&&previous!=page){
   if(::scroll.isInitialized)scroll.smoothScrollTo(0,0)
   val dir=if(order.indexOf(page)>=order.indexOf(previous))1 else -1
   pages[page]?.let{p->p.animate().cancel();p.alpha=1f;p.translationX=0f;for(i in 0 until p.childCount){val c=p.getChildAt(i);c.animate().cancel();enter(c,30L*i,dir*dp(28).toFloat(),0f)}}
  }
  if(page=="update")checkUpdate()
 }
 private fun modeName(mode:String)=if(mode=="auto")"Автовыбор" else mode.uppercase()
 private fun active()=ChamVpnService.lifecycle in setOf(VpnLifecycleState.STARTING,VpnLifecycleState.RUNNING,VpnLifecycleState.STOPPING)
 override fun onNewIntent(intent:Intent){super.onNewIntent(intent);setIntent(intent);acceptIntent(intent)}
 private fun linkToken(value:String):String {val trimmed=value.trim();if(!trimmed.startsWith("https://"))return trimmed;val uri=Uri.parse(trimmed);require(uri.scheme=="https"&&uri.host=="vpn.example.com"&&uri.port==-1&&uri.path=="/vpn/activate"){"Неверная QR-ссылка"};return uri.fragment.orEmpty().removePrefix("token=")}
 private fun acceptIntent(intent:Intent?){val uri=intent?.data?:return;intent.data=null;if(uri.scheme!="https"||uri.host!="vpn.example.com"||uri.port!=-1||uri.path!="/vpn/activate")return;if(active()){setLabel(notice,"Сначала отключите VPN и повторно откройте QR.");return};AlertDialog.Builder(this).setTitle("Персональный доступ").setMessage("Сохранить ключ и привязать его к этой установке?").setNegativeButton("Отмена",null).setPositiveButton("Активировать"){_,_->saveToken(uri.toString())}.show()}
 private fun saveToken(value:String){if(active()||busy.get())return;try{store.setActivationToken(linkToken(value));hasKey=true;token.text.clear();setLabel(notice,"Ключ сохранён. Откройте VPN и подключитесь.");notice.setTextColor(mint);render()}catch(_:Exception){notice.setTextColor(Color.rgb(255,172,166));setLabel(notice,"Неверный формат ключа. Вставьте ключ или QR-ссылку из бота.")}}
 private fun openWebsite(suffix:String=""){try{startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(ActivationClient.WEBSITE+suffix)))}catch(_:Exception){setLabel(notice,"Откройте сайт Chameleon в браузере.")}}
 private fun toggle(){if(active()){if(ChamVpnService.lifecycle==VpnLifecycleState.STOPPING)return;requestPhase=ChamVpnService.lifecycle;stopRequestedAt=SystemClock.uptimeMillis();startRequestedAt=0;startService(Intent(this,ChamVpnService::class.java).setAction(ChamVpnService.ACTION_STOP));render();kick();return};if(busy.get())return;if(!hasKey){showPage("access");return};busy.set(true);setLabel(notice,"");render();Thread({try{ActivationClient.refresh(store);handler.post{if(!destroyed){val permission=VpnService.prepare(this);if(permission==null)startVpn() else @Suppress("DEPRECATION")startActivityForResult(permission,100)}}}catch(error:Exception){handler.post{if(!destroyed){notice.setTextColor(Color.rgb(255,172,166));setLabel(notice,error.message?:"Сервис недоступен. Повторите попытку.")}}}finally{handler.post{busy.set(false);if(!destroyed)render()}}},"chameleon-activation").start()}
 @Deprecated("Android permission bridge")override fun onActivityResult(requestCode:Int,resultCode:Int,data:Intent?){super.onActivityResult(requestCode,resultCode,data);if(requestCode==100){if(resultCode==RESULT_OK)startVpn() else setLabel(notice,"Разрешение VPN не выдано.")}}
 private fun startVpn(){if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)!=android.content.pm.PackageManager.PERMISSION_GRANTED){val prefs=getSharedPreferences("permission",MODE_PRIVATE);if(!prefs.getBoolean("notification_asked",false)){prefs.edit().putBoolean("notification_asked",true).apply();requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),200)}};requestPhase=ChamVpnService.lifecycle;startRequestedAt=SystemClock.uptimeMillis();stopRequestedAt=0;ContextCompat.startForegroundService(this,Intent(this,ChamVpnService::class.java).setAction(ChamVpnService.ACTION_START));render();kick()}
 private fun render(){
  if(page=="update"||updatePhase==UpdatePhase.DOWNLOADING)renderUpdate()
  val phase=if(pendingStop())VpnLifecycleState.STOPPING else if(pendingStart())VpnLifecycleState.STARTING else ChamVpnService.lifecycle
  val connected=phase==VpnLifecycleState.RUNNING&&mobilecore.Mobilecore.connectionStatus()=="connected"
  setLabelSmooth(status,when{busy.get()->"Проверяем доступ…";phase==VpnLifecycleState.STARTING->"Подключаемся…";phase==VpnLifecycleState.STOPPING->"Отключаемся…";connected->"Соединение защищено";phase==VpnLifecycleState.RUNNING->"Восстанавливаем связь";ChamVpnService.lastError.isNotEmpty()->"Ошибка подключения";else->"Готов к подключению"})
  setLabelSmooth(description,when{connected->"VPN подключён · ${mobilecore.Mobilecore.mode().uppercase()}";phase==VpnLifecycleState.RUNNING->"Туннель остаётся поднят. Восстанавливаем сеанс.";ChamVpnService.lastError.isNotEmpty()->ChamVpnService.lastError;busy.get()||phase==VpnLifecycleState.STARTING->"Проверяем доступ и устанавливаем соединение.";!hasKey->"Сначала получите персональный QR-код в боте.";else->"Выбран ${modeName(selected)}. Ваш трафик пока не защищён VPN."})
  val on=phase==VpnLifecycleState.STARTING||phase==VpnLifecycleState.RUNNING||phase==VpnLifecycleState.STOPPING
  setLabel(power,if(on)"Отключить VPN" else if(hasKey)"Подключить VPN" else "Активировать доступ");setActive(power,!busy.get()&&phase!=VpnLifecycleState.STOPPING)
  setFill(power,if(on)Color.rgb(52,70,96) else accent)
  setLabel(traffic,if(connected)"↑ ${formatBytes(mobilecore.Mobilecore.upBytes())}   ↓ ${formatBytes(mobilecore.Mobilecore.downBytes())}" else "↑ 0 Б   ↓ 0 Б")
  setLabel(accessStatus,if(hasKey)"Ключ сохранён. Он проверяется при подключении." else "Вставьте персональный ключ или QR-ссылку из бота.")
  setActive(save,!active()&&!busy.get());token.isEnabled=save.isEnabled
  setLabel(ruDirectButton,if(ruDirect)"Включено · нажмите, чтобы выключить" else "Выключено · нажмите, чтобы включить");setFill(ruDirectButton,if(ruDirect)accent else Color.rgb(35,50,71));setActive(ruDirectButton,!active()&&!busy.get())
  for((mode,b) in protocolButtons){setLabel(b,if(mode==selected)"Выбран ${modeName(mode)}" else "Выбрать ${modeName(mode)}");setFill(b,if(mode==selected)accent else Color.rgb(35,50,71));setActive(b,!active()&&!busy.get())}
  val color=if(connected)mint else if(ChamVpnService.lastError.isNotEmpty()&&!on)Color.rgb(255,172,166) else Color.rgb(143,191,247)
  mark.show(color,when{busy.get()||phase==VpnLifecycleState.STARTING||phase==VpnLifecycleState.STOPPING||(phase==VpnLifecycleState.RUNNING&&!connected)->PowerMark.Mode.BUSY;connected->PowerMark.Mode.ON;else->PowerMark.Mode.IDLE},motion())
 }
 private fun formatBytes(n:Long):String=if(n<1048576)"${n/1024} КиБ" else "%.1f МиБ".format(n/1048576.0)
 override fun onResume(){super.onResume();handler.removeCallbacks(ticker);handler.post(ticker);mark.resume();renderUpdate()}
 override fun onPause(){handler.removeCallbacks(ticker);mark.pause();super.onPause()}
 override fun onSaveInstanceState(out:Bundle){out.putString("page",page);super.onSaveInstanceState(out)}
 override fun onDestroy(){destroyed=true;handler.removeCallbacksAndMessages(null);super.onDestroy()}
 /** Power button art. IDLE: still. BUSY: orbiting arc. ON: slow "breathing" halo. Colour blends. */
 private class PowerMark(context:android.content.Context):View(context){
  enum class Mode { IDLE, BUSY, ON }
  private var tint=Color.rgb(143,191,247)
  private var tintTarget=tint
  private var mode=Mode.IDLE
  private var phase=0f
  private var animated=true
  private var paused=false
  private val pen=Paint(Paint.ANTI_ALIAS_FLAG)
  private val box=RectF()
  private var tintAnimator:ValueAnimator?=null
  private val loop=ValueAnimator.ofFloat(0f,1f).apply{repeatCount=ValueAnimator.INFINITE;interpolator=LinearInterpolator();addUpdateListener{phase=it.animatedValue as Float;invalidate()}}
  fun show(color:Int,next:Mode,motion:Boolean){
   animated=motion
   if(color!=tintTarget){
    tintTarget=color;tintAnimator?.cancel()
    if(motion)tintAnimator=ValueAnimator.ofObject(ArgbEvaluator(),tint,color).apply{duration=420;interpolator=DecelerateInterpolator();addUpdateListener{tint=it.animatedValue as Int;invalidate()};start()}
    else{tint=color;invalidate()}
   }
   if(next!=mode){mode=next;restart();invalidate()}
  }
  private fun restart(){
   loop.cancel();phase=0f
   if(mode==Mode.IDLE||!animated||paused||!isAttachedToWindow)return
   loop.duration=if(mode==Mode.BUSY)1100 else 2600;loop.start()
  }
  fun pause(){paused=true;loop.cancel()}
  fun resume(){paused=false;restart()}
  override fun onAttachedToWindow(){super.onAttachedToWindow();restart()}
  override fun onDetachedFromWindow(){loop.cancel();tintAnimator?.cancel();super.onDetachedFromWindow()}
  override fun onDraw(c:Canvas){
   super.onDraw(c);val scale=minOf(width,height)/112f;c.save();c.translate((width-112f*scale)/2f,(height-112f*scale)/2f);c.scale(scale,scale)
   val cx=56f;val cy=56f
   if(mode==Mode.ON){
    // Two expanding rings, half a cycle apart.
    for(k in 0..1){val t=(phase+k*.5f)%1f;pen.style=Paint.Style.STROKE;pen.strokeWidth=2f;pen.color=tint;pen.alpha=((1f-t)*110).toInt();c.drawCircle(cx,cy,40f+15f*t,pen)}
   }
   pen.style=Paint.Style.FILL;pen.color=Color.rgb(37,59,83);pen.alpha=255;c.drawCircle(cx,cy,40f,pen)
   if(mode==Mode.ON){pen.color=tint;pen.alpha=(28+22*kotlin.math.sin(phase*2*Math.PI).toFloat()).toInt().coerceIn(0,255);c.drawCircle(cx,cy,40f,pen)}
   if(mode==Mode.BUSY){
    pen.style=Paint.Style.STROKE;pen.strokeWidth=3.5f;pen.strokeCap=Paint.Cap.ROUND;pen.color=tint;pen.alpha=230
    box.set(cx-47f,cy-47f,cx+47f,cy+47f);val sweep=70f+50f*kotlin.math.sin(phase*2*Math.PI).toFloat()
    c.drawArc(box,phase*360f-90f,sweep,false,pen)
   }
   pen.style=Paint.Style.STROKE;pen.strokeWidth=3f;pen.strokeCap=Paint.Cap.ROUND;pen.color=tint;pen.alpha=255
   box.set(cx-19f,cy-19f,cx+19f,cy+19f);c.drawArc(box,-50f,280f,false,pen);c.drawLine(cx,cy-22f,cx,cy,pen)
   c.restore()
  }
 }
}
