using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
namespace Chameleon.Windows;
// 4.5.1: window-level motion — page transitions, the sliding section marker, the animated power mark, card hover,
// the start-up intro and pausing of endless animations while the window is hidden or minimized.
// Visual only: connection, key and update state are decided in MainWindow.xaml.cs.
public partial class MainWindow {
 static readonly string[] PageOrder={"Home","Access","Protocol","Diagnostics","Updates"};
 static readonly Color NavOn=Colors.White,NavOff=Color.FromRgb(185,198,214),CardLine=Color.FromRgb(52,70,93),CardHover=Color.FromRgb(76,99,132);
 string currentPage="",powerState="";bool preparing,introDone,wasLive;
 StackPanel[] Pages=>new[]{Home,Access,Protocol,Diagnostics,Updates};
 Button[] NavButtons=>new[]{NavHome,NavAccess,NavProtocol,NavDiagnostics,NavUpdates};
 bool Live=>IsVisible&&WindowState!=WindowState.Minimized;

 void ShowPage(string name){
  var target=Pages.FirstOrDefault(p=>p.Name==name);if(target==null)return;
  bool changed=currentPage!=name||target.Visibility!=Visibility.Visible;
  int from=Array.IndexOf(PageOrder,currentPage),to=Array.IndexOf(PageOrder,name);
  foreach(var p in Pages)p.Visibility=ReferenceEquals(p,target)?Visibility.Visible:Visibility.Collapsed;
  currentPage=name;
  foreach(var b in NavButtons)Motion.Paint(b,Control.ForegroundProperty,(string)b.Tag==name?NavOn:NavOff,200);
  if(!IsLoaded)return;
  MoveIndicator(changed);
  if(changed&&Live)Motion.Enter(target,from<0?0:Math.Sign(to-from));
 }
 void MoveIndicator(bool animate,int attempt=0){
  try{
   var b=NavButtons.FirstOrDefault(x=>(string)x.Tag==currentPage);if(b==null)return;
   if(b.ActualHeight<1){if(attempt<5)Dispatcher.BeginInvoke(DispatcherPriority.Loaded,new Action(()=>MoveIndicator(false,attempt+1)));return;}
   // Layout offset inside NavList (render transforms such as the press scale are not included).
   NavIndicator.Height=b.ActualHeight;
   Motion.MoveY(NavIndicator,VisualTreeHelper.GetOffset(b).Y,animate);
   if(animate)Motion.Stretch(NavAccent);
  }catch{}
 }
 void UpdatePower(){
  string state=reply.State=="connected"?"connected":(operation||preparing||reply.State is "connecting" or "reconnecting")?"busy":code.Length>0?"error":"idle";
  string previous=powerState;
  if(state!=previous){
   powerState=state;
   Motion.Paint(PowerDisc,Border.BackgroundProperty,state switch{"connected"=>Color.FromRgb(29,70,66),"error"=>Color.FromRgb(69,48,58),_=>Color.FromRgb(34,60,83)},320);
   Motion.Paint(PowerIcon,Shape.StrokeProperty,state switch{"connected"=>Color.FromRgb(124,222,201),"error"=>Color.FromRgb(255,168,157),_=>Color.FromRgb(143,198,255)},320);
   if(previous.Length>0&&Live){if(state=="connected")Motion.Bounce(PowerDisc,1.08,160,560);else if(state=="error")Motion.Shake(PowerDisc);}
  }
  Ambient();
 }
 // Endless animations run only while the window is on screen; returning from the tray replays the section entrance.
 void Ambient(){
  bool live=Live;
  Motion.Spin(PowerSpinner,live&&powerState=="busy");
  Motion.Breathe(PowerRingA,PowerRingB,live&&powerState=="connected");
  if(live&&!wasLive&&introDone){var page=Pages.FirstOrDefault(p=>p.Name==currentPage);if(page!=null)Motion.Enter(page,0);}
  wasLive=live;
 }
 void HookCards(){
  try{
   if(TryFindResource("Card") is not Style card)return;
   foreach(var border in Descendants<Border>(this)){
    if(!ReferenceEquals(border.Style,card))continue;var c=border;
    c.MouseEnter+=(_,_)=>Motion.Paint(c,Border.BorderBrushProperty,CardHover,160);
    c.MouseLeave+=(_,_)=>Motion.Paint(c,Border.BorderBrushProperty,CardLine,280);
   }
  }catch{}
 }
 static IEnumerable<T> Descendants<T>(DependencyObject root) where T:DependencyObject{
  foreach(var child in LogicalTreeHelper.GetChildren(root)){
   if(child is not DependencyObject d)continue;
   if(d is T match)yield return match;
   foreach(var nested in Descendants<T>(d))yield return nested;
  }
 }
 void Intro(){
  if(introDone)return;introDone=true;
  if(!Motion.Enabled)return;
  try{
   Motion.Rise(Brand,0,10,360);Motion.PopIn(LogoMark,60);
   var nav=NavButtons;int selected=Math.Max(0,Array.FindIndex(nav,b=>(string)b.Tag==currentPage));
   for(int i=0;i<nav.Length;i++)Motion.Shift(nav[i],110+i*45,-16,340);
   Motion.FadeIn(NavIndicator,230+selected*45,260);
   Motion.Rise(SideFooter,360,6,320);
   var page=Pages.FirstOrDefault(p=>p.Name==currentPage);if(page!=null)Motion.Enter(page,0);
  }catch{}
 }
}
