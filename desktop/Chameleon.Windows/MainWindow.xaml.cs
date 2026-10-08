using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Forms=System.Windows.Forms;
namespace Chameleon.Windows;
public partial class MainWindow : Window {
 readonly CancellationTokenSource shutdown=new();readonly DispatcherTimer timer=new(){Interval=TimeSpan.FromSeconds(3)};
 Credentials? credentials; string protocol="auto";Reply reply=new(){State="disconnected"};bool busy,operation,brokerReady,exiting,trayHintShown;string code="",detail="",system="";DateTime checkedAt;
 UpdateInfo? update;bool updating;DateTime updateCheckedAt;
 Forms.NotifyIcon? tray;Forms.ToolStripMenuItem? trayToggle;
 public MainWindow(){InitializeComponent();VersionText.Text=AppInfo.Version+" "+AppInfo.Channel;Page(App.Updated?"Updates":"Home");FitToScreen();UpdateUi();IsVisibleChanged+=(_,_)=>Ambient();StateChanged+=(_,_)=>Ambient();}
 void FitToScreen(){var area=SystemParameters.WorkArea;if(Height>area.Height-8)Height=Math.Max(420,area.Height-8);if(Width>area.Width-8)Width=Math.Max(600,area.Width-8);}
 async void LoadedWindow(object sender,RoutedEventArgs e){
  MoveIndicator(false);HookCards();Intro();
  CreateTray();Updater.Cleanup();_=CheckForUpdates();
  try{credentials=Vault.Load();protocol=Vault.Protocol();if(!string.IsNullOrEmpty(App.Activation)){credentials=credentials with{Token=Vault.ParseToken(App.Activation)};Vault.Save(credentials);App.Activation=null;Page("Access");Motion.SetText(AccessNotice,"Ключ сохранён. Можно подключаться.");}}
  catch{code="vault.read";detail="Не удалось прочитать ключ для текущего пользователя Windows. Хранилище сохранено без изменений.";}
  Update();
  // Ask once for every system change the VPN needs, then repair services we are allowed to start.
  if(!Vault.SystemConsent())RequestSystemConsent();
  if(Vault.SystemConsent())await Prepare();
  timer.Tick+=async(_,_)=>{if(!busy)await Refresh();};timer.Start();if(credentials!=null)await Refresh();
 }
 bool RequestSystemConsent(){
  var answer=MessageBox.Show(this,
   "Для работы VPN Chameleon внесёт в систему следующие изменения:\n\n"+
   "• запустит и будет поддерживать службу «ChameleonBroker»;\n"+
   "• запустит службы «Брандмауэр Защитника Windows» и «Base Filtering Engine», если они остановлены;\n"+
   "• на время подключения создаст сетевой адаптер Wintun «ChameleonFree»;\n"+
   "• на время подключения изменит маршруты и DNS, чтобы трафик шёл через VPN;\n"+
   "• на время подключения добавит правила брандмауэра ChameleonFree-* против утечек DNS и IPv6.\n\n"+
   "При отключении маршруты, DNS и правила снимаются. Правила других программ не изменяются.\n\nРазрешить эти изменения?",
   "Chameleon VPN — разрешения",MessageBoxButton.YesNo,MessageBoxImage.Question,MessageBoxResult.Yes);
  bool ok=answer==MessageBoxResult.Yes;try{Vault.SystemConsent(ok);}catch{}
  if(!ok){code="system.consent";detail="Без разрешения на изменения системы VPN не сможет подключиться. Нажмите «Подключить VPN», чтобы разрешить.";Update();}
  return ok;
 }
 async Task Prepare(){
  try{var result=await Task.Run(SystemPrep.Ensure);system=result.Summary;if(!result.Ok&&code.Length==0){code=result.Code;detail=result.Detail;}}
  catch{system="Службы: проверка не выполнена";}
  Update();
 }
 void CreateTray(){
  if(tray!=null)return;
  var menu=new Forms.ContextMenuStrip();
  menu.Items.Add("Открыть Chameleon",null,(_,_)=>ShowFromTray());
  trayToggle=new Forms.ToolStripMenuItem("Подключить VPN",null,async(_,_)=>{ShowFromTray();await ToggleConnection();});menu.Items.Add(trayToggle);
  menu.Items.Add(new Forms.ToolStripSeparator());
  menu.Items.Add("Выход",null,async(_,_)=>await ExitApplication());
  System.Drawing.Icon? icon=null;try{icon=System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath??"");}catch{}
  tray=new Forms.NotifyIcon{Icon=icon??System.Drawing.SystemIcons.Application,Text="Chameleon VPN",Visible=true,ContextMenuStrip=menu};
  tray.DoubleClick+=(_,_)=>ShowFromTray();tray.MouseClick+=(_,a)=>{if(a.Button==Forms.MouseButtons.Left)ShowFromTray();};
  App.ShowRequested+=()=>Dispatcher.BeginInvoke(()=>{ReloadVaultIfIdle();ShowFromTray();});
 }
 void ReloadVaultIfIdle(){if(busy||reply.State is "connected" or "reconnecting")return;try{credentials=Vault.Load();Update();}catch{}}
 internal void ShowFromTray(){Show();if(WindowState==WindowState.Minimized)WindowState=WindowState.Normal;Activate();Topmost=true;Topmost=false;Focus();}
 void ClosingWindow(object? sender,CancelEventArgs e){
  if(exiting)return;
  // The close button hides to the notification area; "Выход" in the tray menu really quits.
  e.Cancel=true;Hide();
  if(!trayHintShown&&tray!=null){trayHintShown=true;try{tray.ShowBalloonTip(3000,"Chameleon VPN","Приложение продолжает работать в трее. Для выхода нажмите правой кнопкой на значок.",Forms.ToolTipIcon.Info);}catch{}}
 }
 async Task ExitApplication(){
  if(exiting)return;
  if(reply.State is "connected" or "reconnecting" or "connecting"){
   ShowFromTray();
   var answer=MessageBox.Show(this,"VPN подключён. Отключить VPN и выйти?","Chameleon VPN",MessageBoxButton.YesNo,MessageBoxImage.Question,MessageBoxResult.Yes);
   if(answer!=MessageBoxResult.Yes)return;
   await Exchange("disconnect");
  }
  exiting=true;Close();System.Windows.Application.Current.Shutdown();
 }
 void ClosedWindow(object? sender,EventArgs e){timer.Stop();shutdown.Cancel();shutdown.Dispose();if(tray!=null){tray.Visible=false;tray.Dispose();tray=null;}}
 void Page(string name){ShowPage(name);if(name=="Updates"&&IsLoaded&&!updating&&DateTime.Now-updateCheckedAt>TimeSpan.FromMinutes(5))_=CheckForUpdates();}
 void Navigate(object sender,RoutedEventArgs e)=>Page((string)((Button)sender).Tag);
 void OpenAccess(object sender,RoutedEventArgs e)=>Page("Access");
 async Task Refresh()=>await Exchange("status");
 async Task Exchange(string command){
  if(busy)return;busy=true;operation=command!="status";if(operation)Update();
  try {reply=await BrokerClient.Call(command,protocol,command=="connect"?credentials:null,shutdown.Token,command=="connect"?Vault.RuDirect():null);brokerReady=true;code=reply.Code??"";detail=reply.Message;}
  catch(SafeFailure f){brokerReady=false;reply=new(){State="error"};code=f.Code;detail=f.Message;}
  catch{brokerReady=false;reply=new(){State="error"};code="ipc.internal";detail="Не удалось завершить безопасный обмен со службой.";}
  finally{busy=false;operation=false;checkedAt=DateTime.Now;Update();}
 }
 async void Connect(object sender,RoutedEventArgs e)=>await ToggleConnection();
 async Task ToggleConnection(){
  if(busy||preparing)return;if(credentials==null){Page("Diagnostics");return;}if(credentials.Token.Length==0){Page("Access");return;}
  bool disconnect=reply.State is "connected" or "reconnecting";
  if(!disconnect){
   if(!Vault.SystemConsent()&&!RequestSystemConsent())return;
   // Respond at once: the service check below can take a few seconds on a cold start.
   preparing=true;Motion.SetText(StatusTitle,"Устанавливаем соединение");Motion.SetText(StatusDetail,"Проверяем службы Windows…");Update();
   try{await Prepare();}finally{preparing=false;}
   if(!brokerReady&&code.StartsWith("system.",StringComparison.Ordinal)){Update();return;}
  }
  // A background status refresh may still be in flight: wait for it instead of dropping the command.
  for(int i=0;i<40&&busy;i++)await Task.Delay(100);
  Motion.SetText(StatusTitle,disconnect?"Отключаем VPN":"Устанавливаем соединение");Motion.SetText(StatusDetail,disconnect?"Снимаем маршруты и защитные правила…":protocol=="auto"?"AUTO: проверяем KS и CITP…":"Проверяем доступ и защиту соединения…");
  await Exchange(disconnect?"disconnect":"connect");
 }
 async void Check(object sender,RoutedEventArgs e){Motion.SetText(DiagnosticTitle,"Проверяем службу и компоненты…");await Prepare();await Refresh();}
 void SaveKey(object sender,RoutedEventArgs e){
  if(busy||reply.State is "connected" or "reconnecting"){Motion.SetText(AccessNotice,"Сначала отключите VPN.",flash:true);return;}
  try{if(credentials==null)throw new InvalidOperationException();var changed=credentials with{Token=Vault.ParseToken(KeyInput.Password)};Vault.Save(changed);credentials=changed;KeyInput.Clear();Motion.SetText(AccessNotice,"Ключ сохранён. Откройте «Подключение» и нажмите «Подключить VPN».",flash:true);Update();}
  catch(FormatException){Motion.SetText(AccessNotice,"Вставьте полный подписанный ключ или QR-ссылку из официального бота.",flash:true);}
  catch{Motion.SetText(AccessNotice,"Не удалось сохранить ключ. Предыдущее хранилище не сбрасывалось.",flash:true);}
 }
 void ToggleRuDirect(object sender,RoutedEventArgs e){
  if(busy||reply.State is "connected" or "reconnecting"){Motion.SetText(ProtocolNotice,"Сначала отключите VPN.",flash:true);return;}
  try{bool next=!Vault.RuDirect();Vault.RuDirect(next);Motion.SetText(ProtocolNotice,next?"Российские сайты пойдут напрямую со следующего подключения.":"Весь трафик пойдёт через VPN со следующего подключения.",flash:true);Update();}catch{Motion.SetText(ProtocolNotice,"Не удалось сохранить настройку.",flash:true);}
 }
 void ChooseProtocol(object sender,RoutedEventArgs e){
  if(busy||reply.State is "connected" or "reconnecting"){Motion.SetText(ProtocolNotice,"Сначала отключите VPN.",flash:true);return;}
  try{string choice=(string)((Button)sender).Tag;Vault.Protocol(choice);protocol=choice;Motion.SetText(ProtocolNotice,"Выбор сохранён. Применится при подключении.",flash:true);Update();}catch{Motion.SetText(ProtocolNotice,"Не удалось сохранить выбор протокола.",flash:true);}
 }
 static void Open(string url){try{Process.Start(new ProcessStartInfo(url){UseShellExecute=true});}catch{}}
 void OpenBot(object sender,RoutedEventArgs e)=>Open("https://t.me/your_activation_bot");
 void CopyReport(object sender,RoutedEventArgs e){try{Clipboard.SetText($"Chameleon {AppInfo.Version} {AppInfo.Channel} / WPF (admin)\nWindows IPC diagnostics\nBrokerReady: {brokerReady.ToString().ToLowerInvariant()}\nState: {reply.State}\nProtocol: {protocol.ToUpperInvariant()}{(reply.Mode!=null?" / "+reply.Mode:"")}\nSystem: {system}\nChecked: {checkedAt:HH:mm:ss}\nCode: {(code.Length==0?"ok":code)}\nDetail: {detail}\nCredentials/tokens/traffic: not included");Motion.SetText(CopyNotice,"Отчёт скопирован.",flash:true);}catch{Motion.SetText(CopyNotice,"Буфер обмена занят. Повторите.",flash:true);}}
 void CheckUpdates(object sender,RoutedEventArgs e){if(!updating)_=CheckForUpdates();}
 async Task CheckForUpdates(){
  if(updating)return;updating=true;Motion.SetText(UpdateTitle,"Проверяем обновления");Motion.SetText(UpdateDetail,"Связываемся с сайтом Chameleon…");UpdateUi();
  try{
   var u=await Updater.Check(shutdown.Token);
   if(Updater.Newer(u.Version)){
    update=u;Motion.SetText(UpdateTitle,"Доступна версия "+u.Version);
    Motion.SetText(UpdateDetail,Updater.Installed?"Размер "+Bytes((ulong)u.Size)+". Нажмите «Обновить»: установщик скачается, будет проверен и запустится автоматически.":"Эта копия запущена не из Program Files. Скачайте установщик с сайта и установите его.");
   }else{update=null;Motion.SetText(UpdateTitle,"Установлена последняя версия");Motion.SetText(UpdateDetail,App.Updated?"Обновление установлено. Chameleon "+AppInfo.Version+" готов к работе.":"На сайте версия "+u.Version+". Обновление не требуется.");}
  }
  catch(SafeFailure f){Motion.SetText(UpdateTitle,"Не удалось проверить обновления");Motion.SetText(UpdateDetail,f.Message);}
  catch(OperationCanceledException){}
  catch{Motion.SetText(UpdateTitle,"Не удалось проверить обновления");Motion.SetText(UpdateDetail,"Нет связи с сайтом обновлений. Проверьте интернет и повторите.");}
  finally{updating=false;updateCheckedAt=DateTime.Now;UpdateUi();}
 }
 async void InstallUpdate(object sender,RoutedEventArgs e){
  if(update==null||updating||exiting)return;var u=update;
  if((reply.State is "connected" or "reconnecting" or "connecting")&&MessageBox.Show(this,"Для установки обновления VPN будет отключён. Продолжить?","Chameleon VPN",MessageBoxButton.YesNo,MessageBoxImage.Question,MessageBoxResult.Yes)!=MessageBoxResult.Yes)return;
  updating=true;UpdateUi();Motion.ResetProgress(UpdateProgress);UpdateProgress.Visibility=Visibility.Visible;Motion.FadeIn(UpdateProgress);Motion.SetText(UpdateTitle,"Скачиваем версию "+u.Version);Motion.SetText(UpdateDetail,"Загрузка начинается…");
  try{
   bool downloading=true;
   var progress=new Progress<double>(v=>{if(!downloading)return;Motion.Advance(UpdateProgress,v);Motion.SetText(UpdateDetail,"Загружено "+Bytes((ulong)(v*u.Size))+" из "+Bytes((ulong)u.Size)+".",animate:false);});
   string path=await Updater.Download(u,progress,shutdown.Token);downloading=false;
   for(int i=0;i<150&&busy;i++)await Task.Delay(100);
   if(reply.State is "connected" or "reconnecting" or "connecting"){
    Motion.SetText(UpdateTitle,"Отключаем VPN");Motion.SetText(UpdateDetail,"Снимаем маршруты и защитные правила перед установкой…");
    await Exchange("disconnect");
    if(reply.State is "connected" or "reconnecting")throw new SafeFailure("update.disconnect","Не удалось отключить VPN. Отключите его вручную и повторите обновление.");
   }
   Motion.SetText(UpdateTitle,"Проверяем установщик");Motion.SetText(UpdateDetail,"Сверяем размер, SHA-256 и версию…");
   await Task.Run(()=>Updater.Launch(u,path));
   Motion.SetText(UpdateTitle,"Устанавливаем обновление");Motion.SetText(UpdateDetail,"Приложение закроется и откроется снова через несколько секунд.");
   await Task.Delay(700);
   exiting=true;Close();System.Windows.Application.Current.Shutdown();
  }
  catch(SafeFailure f){Motion.SetText(UpdateTitle,"Обновление не установлено");Motion.SetText(UpdateDetail,f.Message);}
  catch(OperationCanceledException){}
  catch{Motion.SetText(UpdateTitle,"Обновление не установлено");Motion.SetText(UpdateDetail,"Не удалось подготовить обновление. Повторите попытку.");}
  finally{if(!exiting){updating=false;UpdateProgress.Visibility=Visibility.Hidden;UpdateUi();}}
 }
 void UpdateUi(){
  CheckUpdateButton.IsEnabled=!updating;UpdateButton.IsEnabled=!updating&&update!=null&&Updater.Installed;
  Motion.SetContent(UpdateButton,update!=null?"Обновить до "+update.Version:"Обновить");if(Motion.SetContent(NavUpdates,update!=null?"Обновления  •":"Обновления")&&update!=null)Motion.Pulse(NavUpdates,0.94);
  Motion.SetText(InstalledVersion,"Установлена версия "+AppInfo.Version+" "+AppInfo.Channel+(updateCheckedAt==default?"":" · проверено в "+updateCheckedAt.ToString("HH:mm")));
 }
 static string Bytes(ulong n)=>n>=1073741824?(n/1073741824d).ToString("0.00",CultureInfo.CurrentCulture)+" ГиБ":n>=1048576?(n/1048576d).ToString("0.0",CultureInfo.CurrentCulture)+" МиБ":n>=1024?(n/1024d).ToString("0.0",CultureInfo.CurrentCulture)+" КиБ":n+" Б";
 static string Label(string p)=>p=="auto"?"AUTO":p.ToUpperInvariant();
 void Update(){
  bool active=reply.State is "connected" or "reconnecting";bool hasKey=credentials?.Token.Length>0;bool working=operation||preparing;
  SaveButton.IsEnabled=!working&&!active&&credentials!=null;ChooseAuto.IsEnabled=ChooseCitp.IsEnabled=ChooseKs.IsEnabled=RuDirectToggle.IsEnabled=!working&&!active;CheckButton.IsEnabled=ConnectButton.IsEnabled=!working;
  // The indeterminate bar animates only while its slot is open (no hidden CPU use).
  if(Motion.Reveal(ProgressSlot,15,working)){if(working)Progress.IsIndeterminate=true;else Motion.After(260,()=>{if(!operation&&!preparing)Progress.IsIndeterminate=false;});}
  Motion.SetText(SelectedProtocol,reply.State=="connected"&&reply.Mode!=null?reply.Mode:Label(protocol));Uploaded.Text=Bytes(reply.Up);Downloaded.Text=Bytes(reply.Down);
  Motion.SetText(KeyStatus,hasKey?"Сохранён · проверяется при подключении":"Ключ пока не добавлен");
  bool direct=Vault.RuDirect();Motion.SetContent(RuDirectToggle,direct?"Включено":"Выключено");Motion.Paint(RuDirectToggle,Control.BackgroundProperty,direct?Color.FromRgb(34,109,181):Color.FromRgb(37,53,74));
  foreach(var (button,tag) in new[]{(ChooseAuto,"auto"),(ChooseCitp,"citp"),(ChooseKs,"ks")}){Motion.SetContent(button,(protocol==tag?"Выбран ":"Выбрать ")+Label(tag));Motion.Paint(button,Control.BackgroundProperty,protocol==tag?Color.FromRgb(34,109,181):Color.FromRgb(37,53,74));}
  if(!busy&&!preparing){
   Motion.SetText(StatusTitle,reply.State=="connected"?"Соединение защищено":reply.State=="reconnecting"?"Восстанавливаем соединение":reply.State=="connecting"?"Устанавливаем соединение":code.Length>0?"Требуется проверка":!hasKey?"Добавьте персональный ключ":"Готов к подключению");
   Motion.SetText(StatusDetail,code.Length>0?detail:reply.State=="connected"?"VPN подключён · "+(reply.Mode??Label(protocol)):reply.State is "reconnecting" or "connecting"?(detail.Length>0?detail:"Туннель временно недоступен. Защитные правила сохранены."):!hasKey?"Получите ключ в боте и сохраните его в разделе «Мой доступ».":"Выбран "+Label(protocol)+". Ваш трафик пока не защищён VPN.");
  }
  UpdatePower();
  Motion.SetContent(ConnectButton,working?"Пожалуйста, подождите…":active?"Отключить VPN":!hasKey?"Активировать доступ":"Подключить VPN");
  Motion.SetText(DiagnosticTitle,brokerReady?code.Length==0?"Служба отвечает":"Служба отвечает · ошибка подключения":"Связь со службой не подтверждена");
  Motion.SetText(DiagnosticCode,"Код: "+(code.Length==0?"ok":code));Motion.SetText(DiagnosticDetail,detail);Motion.SetText(SystemState,system);CheckedTime.Text="Последняя проверка: "+(checkedAt==default?"—":checkedAt.ToString("HH:mm:ss"));
  if(tray!=null){tray.Text=reply.State=="connected"?"Chameleon VPN — подключено":"Chameleon VPN — не подключено";if(trayToggle!=null){trayToggle.Text=active?"Отключить VPN":"Подключить VPN";trayToggle.Enabled=!working&&hasKey;}}
 }
}
