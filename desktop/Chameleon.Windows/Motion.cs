using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
namespace Chameleon.Windows;
// 4.5.1 motion layer. Animations only decorate values the window has already decided. Every helper is
// idempotent (the 3-second status refresh calls them again and again), interruptible (new motion starts from
// the value currently on screen), follows «Show animations in Windows» (SystemParameters.ClientAreaAnimation)
// and never throws: on any failure the plain value is applied without motion.
internal static class Motion {
 sealed class State {
  internal TransformGroup? Group;internal RotateTransform? Rotate;internal bool Pressed,Hooked,Active,Swapping;
  internal object? Pending;internal long Stamp;internal Dictionary<DependencyProperty,Paintbox>? Paint;
 }
 sealed class Paintbox {internal SolidColorBrush Brush=null!;internal Color Target;}
 static readonly ConditionalWeakTable<DependencyObject,State> states=new();
 static State S(DependencyObject o)=>states.GetValue(o,_=>new State());
 static T Frozen<T>(T value) where T:Freezable{value.Freeze();return value;}
 internal static readonly IEasingFunction Out=Frozen(new CubicEase{EasingMode=EasingMode.EaseOut});
 internal static readonly IEasingFunction In=Frozen(new QuadraticEase{EasingMode=EasingMode.EaseIn});
 internal static readonly IEasingFunction InOut=Frozen(new SineEase{EasingMode=EasingMode.EaseInOut});
 internal static readonly IEasingFunction Spring=Frozen(new BackEase{EasingMode=EasingMode.EaseOut,Amplitude=0.4});
 static readonly Brush RippleFill=Frozen(new SolidColorBrush(Colors.White));
 internal static bool Enabled{get{try{return SystemParameters.ClientAreaAnimation;}catch{return false;}}}
 // Endless loops also need hardware rendering: in software rendering (some RDP sessions) they would cost CPU.
 internal static bool Ambient=>Enabled&&(RenderCapability.Tier>>16)>=1;
 static Duration D(double ms)=>new(TimeSpan.FromMilliseconds(Math.Max(0,ms)));
 static KeyTime K(double ms)=>KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(Math.Max(0,ms)));

 // ---- Buttons: hover glow, press scale with spring release, ripple from the pointer, fade when disabled ----
 static bool installed;
 internal static void Install(){
  if(installed)return;installed=true;
  try{
   var t=typeof(Button);
   EventManager.RegisterClassHandler(t,UIElement.MouseEnterEvent,new MouseEventHandler((s,_)=>Hover(s as Button,true)),true);
   EventManager.RegisterClassHandler(t,UIElement.MouseLeaveEvent,new MouseEventHandler((s,_)=>Hover(s as Button,false)),true);
   EventManager.RegisterClassHandler(t,UIElement.PreviewMouseLeftButtonDownEvent,new MouseButtonEventHandler((s,e)=>Press(s as Button,e)),true);
   EventManager.RegisterClassHandler(t,UIElement.PreviewMouseLeftButtonUpEvent,new MouseButtonEventHandler((s,_)=>Release(s as Button)),true);
   EventManager.RegisterClassHandler(t,UIElement.LostMouseCaptureEvent,new MouseEventHandler((s,_)=>Release(s as Button)),true);
   EventManager.RegisterClassHandler(t,ButtonBase.ClickEvent,new RoutedEventHandler((s,_)=>Clicked(s as Button)),true);
   EventManager.RegisterClassHandler(t,FrameworkElement.LoadedEvent,new RoutedEventHandler((s,_)=>Attach(s as Button)),true);
  }catch{}
 }
 static T? Part<T>(Control c,string name) where T:class{
  try{if(c.Template==null)return null;c.ApplyTemplate();return c.Template.FindName(name,c) as T;}catch{return null;}
 }
 static void Hover(Button? b,bool over){
  if(b==null)return;
  try{
   if(!over)Release(b);
   var glow=Part<UIElement>(b,"Glow");if(glow==null)return;
   double to=over&&b.IsEnabled?0.07:0;
   if(!Enabled){glow.BeginAnimation(UIElement.OpacityProperty,null);glow.Opacity=to;return;}
   glow.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(to,D(over?120:240)){EasingFunction=Out});
  }catch{}
 }
 static void Press(Button? b,MouseButtonEventArgs e){
  if(b==null||!b.IsEnabled)return;
  try{
   S(b).Pressed=true;
   if(!Enabled){if(Part<UIElement>(b,"Glow") is UIElement glow){glow.BeginAnimation(UIElement.OpacityProperty,null);glow.Opacity=0.16;}return;}
   // Wide buttons sink a few pixels, small ones a little more — never a jump.
   Scale(b,Math.Clamp(1-6/Math.Max(b.ActualWidth,1),0.95,0.985),90,Out);
   if(Part<Canvas>(b,"Ripples") is Canvas host)Ripple(host,e.GetPosition(host),0.24);
  }catch{}
 }
 static void Release(Button? b){
  if(b==null)return;var st=S(b);if(!st.Pressed)return;st.Pressed=false;
  try{
   if(Enabled){Scale(b,1,320,Spring);return;}
   var s=ScaleOf(b);s.BeginAnimation(ScaleTransform.ScaleXProperty,null);s.BeginAnimation(ScaleTransform.ScaleYProperty,null);
   if(Part<UIElement>(b,"Glow") is UIElement glow){glow.BeginAnimation(UIElement.OpacityProperty,null);glow.Opacity=b.IsMouseOver&&b.IsEnabled?0.07:0;}
  }catch{}
 }
 static void Clicked(Button? b){
  if(b==null||!Enabled)return;
  try{
   // Space/Enter get the same feedback as a click: a ripple from the centre and a short pulse.
   if(InputManager.Current.MostRecentInputDevice is not KeyboardDevice)return;
   if(Part<Canvas>(b,"Ripples") is Canvas host)Ripple(host,new Point(host.ActualWidth/2,host.ActualHeight/2),0.2);
   Bounce(b,0.97,90,380);
  }catch{}
 }
 static void Attach(Button? b){
  if(b==null)return;var st=S(b);if(st.Hooked)return;st.Hooked=true;
  b.IsEnabledChanged+=(_,e)=>{
   try{
    bool on=e.NewValue is true;Hover(b,on&&b.IsMouseOver);
    var root=Part<UIElement>(b,"Root");if(root==null)return;
    if(!Enabled||!b.IsVisible){root.BeginAnimation(UIElement.OpacityProperty,null);return;}
    // The template trigger owns the resting value (0.5 when disabled); this only animates the change.
    double from=root.HasAnimatedProperties?root.Opacity:on?0.5:1;
    root.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(from,on?1:0.5,D(220)){EasingFunction=Out,FillBehavior=FillBehavior.Stop});
   }catch{}
  };
 }
 static void Scale(UIElement e,double to,double ms,IEasingFunction ease){
  var s=ScaleOf(e);var a=new DoubleAnimation(to,D(ms)){EasingFunction=ease};
  s.BeginAnimation(ScaleTransform.ScaleXProperty,a);s.BeginAnimation(ScaleTransform.ScaleYProperty,a);
 }
 static void Ripple(Canvas host,Point at,double strength){
  double w=host.ActualWidth,h=host.ActualHeight;if(w<2||h<2)return;
  host.Clip=new RectangleGeometry(new Rect(0,0,w,h),10,10);
  double dx=Math.Max(at.X,w-at.X),dy=Math.Max(at.Y,h-at.Y),r=Math.Sqrt(dx*dx+dy*dy);
  var dot=new Ellipse{Width=2*r,Height=2*r,Fill=RippleFill,Opacity=strength,IsHitTestVisible=false};
  var grow=new ScaleTransform(0.08,0.08,r,r);dot.RenderTransform=grow;
  Canvas.SetLeft(dot,at.X-r);Canvas.SetTop(dot,at.Y-r);
  while(host.Children.Count>=4)host.Children.RemoveAt(0);
  host.Children.Add(dot);
  var size=new DoubleAnimation(0.08,1,D(460)){EasingFunction=Out};
  var fade=new DoubleAnimation(strength,0,D(520)){BeginTime=TimeSpan.FromMilliseconds(120),EasingFunction=In};
  fade.Completed+=(_,_)=>host.Children.Remove(dot);
  grow.BeginAnimation(ScaleTransform.ScaleXProperty,size);grow.BeginAnimation(ScaleTransform.ScaleYProperty,size);
  dot.BeginAnimation(UIElement.OpacityProperty,fade);
 }

 // ---- Transforms (created in code, never frozen) ----
 static TransformGroup Group(UIElement e){
  var st=S(e);
  if(st.Group!=null&&ReferenceEquals(e.RenderTransform,st.Group))return st.Group;
  var g=new TransformGroup();g.Children.Add(new ScaleTransform(1,1));g.Children.Add(new TranslateTransform(0,0));
  e.RenderTransformOrigin=new Point(0.5,0.5);e.RenderTransform=g;st.Group=g;return g;
 }
 internal static ScaleTransform ScaleOf(UIElement e)=>(ScaleTransform)Group(e).Children[0];
 internal static TranslateTransform TranslateOf(UIElement e)=>(TranslateTransform)Group(e).Children[1];
 static RotateTransform RotateOf(UIElement e){
  var st=S(e);
  if(st.Rotate!=null&&ReferenceEquals(e.RenderTransform,st.Rotate))return st.Rotate;
  var r=new RotateTransform(0);e.RenderTransformOrigin=new Point(0.5,0.5);e.RenderTransform=r;st.Rotate=r;return r;
 }
 // Holds the start value from t=0 (no flash of the final state during the delay), then eases to the target.
 static DoubleAnimationUsingKeyFrames Hold(double from,double to,double delay,double ms,IEasingFunction? ease=null){
  var a=new DoubleAnimationUsingKeyFrames{FillBehavior=FillBehavior.Stop};
  a.KeyFrames.Add(new DiscreteDoubleKeyFrame(from,K(0)));
  if(delay>0)a.KeyFrames.Add(new DiscreteDoubleKeyFrame(from,K(delay)));
  a.KeyFrames.Add(new EasingDoubleKeyFrame(to,K(delay+ms),ease??Out));
  return a;
 }

 // ---- Entrances ----
 internal static void Rise(UIElement e,double delay,double dy,double ms=300){
  if(!Enabled)return;
  try{e.BeginAnimation(UIElement.OpacityProperty,Hold(0,1,delay,ms*0.85));TranslateOf(e).BeginAnimation(TranslateTransform.YProperty,Hold(dy,0,delay,ms));}catch{}
 }
 internal static void Shift(UIElement e,double delay,double dx,double ms=320){
  if(!Enabled)return;
  try{e.BeginAnimation(UIElement.OpacityProperty,Hold(0,1,delay,ms*0.85));TranslateOf(e).BeginAnimation(TranslateTransform.XProperty,Hold(dx,0,delay,ms));}catch{}
 }
 internal static void FadeIn(UIElement e,double delay=0,double ms=220){
  if(!Enabled)return;
  try{e.BeginAnimation(UIElement.OpacityProperty,Hold(0,1,delay,ms));}catch{}
 }
 internal static void PopIn(UIElement e,double delay){
  if(!Enabled)return;
  try{var s=ScaleOf(e);var a=Hold(0.6,1,delay,480,Spring);s.BeginAnimation(ScaleTransform.ScaleXProperty,a);s.BeginAnimation(ScaleTransform.ScaleYProperty,a);e.BeginAnimation(UIElement.OpacityProperty,Hold(0,1,delay,200));}catch{}
 }
 // Page change: the section slides in from the direction of travel, its blocks rise one after another.
 internal static void Enter(Panel page,int direction){
  if(!Enabled)return;
  try{
   if(direction!=0)TranslateOf(page).BeginAnimation(TranslateTransform.XProperty,Hold(28*direction,0,0,360));
   int i=0;foreach(var child in page.Children)if(child is UIElement e&&e.Visibility==Visibility.Visible)Rise(e,Math.Min(i++,7)*40,14,320);
  }catch{}
 }
 internal static void MoveY(UIElement e,double y,bool animate){
  try{
   var t=TranslateOf(e);
   if(!animate||!Enabled){t.BeginAnimation(TranslateTransform.YProperty,null);t.Y=y;return;}
   t.BeginAnimation(TranslateTransform.YProperty,new DoubleAnimation(y,D(380)){EasingFunction=Spring});
  }catch{}
 }
 internal static void Stretch(UIElement e){
  if(!Enabled)return;
  try{var a=new DoubleAnimationUsingKeyFrames{FillBehavior=FillBehavior.Stop};a.KeyFrames.Add(new EasingDoubleKeyFrame(0.35,K(120),Out));a.KeyFrames.Add(new EasingDoubleKeyFrame(1,K(420),Spring));ScaleOf(e).BeginAnimation(ScaleTransform.ScaleYProperty,a);}catch{}
 }
 internal static void Bounce(UIElement e,double peak,double up,double settle){
  if(!Enabled||!e.IsVisible)return;
  try{
   var s=ScaleOf(e);var a=new DoubleAnimationUsingKeyFrames{FillBehavior=FillBehavior.Stop};
   a.KeyFrames.Add(new EasingDoubleKeyFrame(peak,K(up),Out));a.KeyFrames.Add(new EasingDoubleKeyFrame(1,K(settle),Spring));
   s.BeginAnimation(ScaleTransform.ScaleXProperty,a);s.BeginAnimation(ScaleTransform.ScaleYProperty,a);
  }catch{}
 }
 internal static void Pulse(UIElement e,double depth=0.96)=>Bounce(e,depth,90,380);
 internal static void Shake(UIElement e){
  if(!Enabled||!e.IsVisible)return;
  try{
   var a=new DoubleAnimationUsingKeyFrames{FillBehavior=FillBehavior.Stop};double t=0;
   foreach(var x in new[]{-6.0,5,-3,2,0}){t+=70;a.KeyFrames.Add(new EasingDoubleKeyFrame(x,K(t),InOut));}
   TranslateOf(e).BeginAnimation(TranslateTransform.XProperty,a);
  }catch{}
 }
 static void Blink(UIElement e){
  var a=new DoubleAnimationUsingKeyFrames{FillBehavior=FillBehavior.Stop};
  a.KeyFrames.Add(new EasingDoubleKeyFrame(0.25,K(90),Out));a.KeyFrames.Add(new EasingDoubleKeyFrame(1,K(320),Out));
  e.BeginAnimation(UIElement.OpacityProperty,a);
 }

 // ---- Values ----
 // Colour of a brush property flows to the new value. Brushes from styles are frozen, so a private brush is used.
 internal static void Paint(DependencyObject o,DependencyProperty p,Color to,double ms=220){
  try{
   var st=S(o);st.Paint??=new();
   bool live=Enabled&&o is UIElement u&&u.IsVisible;
   if(st.Paint.TryGetValue(p,out var box)&&ReferenceEquals(o.GetValue(p),box.Brush)){
    if(box.Target==to)return;box.Target=to;
    if(!live){box.Brush.BeginAnimation(SolidColorBrush.ColorProperty,null);box.Brush.Color=to;}
    else box.Brush.BeginAnimation(SolidColorBrush.ColorProperty,new ColorAnimation(to,D(ms)){EasingFunction=Out});
    return;
   }
   Color from=(o.GetValue(p) is SolidColorBrush current)?current.Color:to;
   box=new Paintbox{Brush=new SolidColorBrush(live?from:to),Target=to};st.Paint[p]=box;o.SetValue(p,box.Brush);
   if(live&&from!=to)box.Brush.BeginAnimation(SolidColorBrush.ColorProperty,new ColorAnimation(from,to,D(ms)){EasingFunction=Out});
  }catch{try{o.SetValue(p,new SolidColorBrush(to));}catch{}}
 }
 // Text changes: old text lifts and fades out, the new one settles in. Calls during a change only replace the
 // pending text, so the latest value always wins. animate:false is for fast counters (download progress).
 internal static void SetText(TextBlock t,string? value,bool animate=true,bool flash=false){
  value??="";var st=S(t);
  try{
   if(st.Swapping){st.Pending=value;return;}
   if(t.Text==value){if(flash&&animate&&Enabled&&t.IsVisible)Blink(t);return;}
   if(!animate||!Enabled||!t.IsVisible){t.Text=value;return;}
   var move=TranslateOf(t);
   t.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(0,D(100)){EasingFunction=In});
   move.BeginAnimation(TranslateTransform.YProperty,new DoubleAnimation(-4,D(100)){EasingFunction=In});
   st.Swapping=true;st.Pending=value;
   After(100,()=>{
    st.Swapping=false;var next=st.Pending as string;st.Pending=null;
    try{if(next!=null)t.Text=next;}catch{}
    try{
     t.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(0,1,D(220)){EasingFunction=Out,FillBehavior=FillBehavior.Stop});
     move.BeginAnimation(TranslateTransform.YProperty,new DoubleAnimation(5,0,D(260)){EasingFunction=Out,FillBehavior=FillBehavior.Stop});
    }catch{t.BeginAnimation(UIElement.OpacityProperty,null);move.BeginAnimation(TranslateTransform.YProperty,null);}
   });
  }catch{st.Swapping=false;st.Pending=null;try{t.BeginAnimation(UIElement.OpacityProperty,null);t.Text=value;}catch{}}
 }
 // Button captions cross-fade the same way (template part "Presenter"). Returns true when the caption changes.
 internal static bool SetContent(ContentControl c,object value){
  var st=S(c);
  try{
   if(st.Swapping){bool differs=!Equals(st.Pending,value);st.Pending=value;return differs;}
   if(Equals(c.Content,value))return false;
   var presenter=Part<UIElement>(c,"Presenter");
   if(presenter==null||!Enabled||!c.IsVisible){c.Content=value;return true;}
   presenter.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(0,D(90)){EasingFunction=In});
   st.Swapping=true;st.Pending=value;
   After(90,()=>{
    st.Swapping=false;var next=st.Pending;st.Pending=null;
    try{if(next!=null)c.Content=next;}catch{}
    try{presenter.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(0,1,D(200)){EasingFunction=Out,FillBehavior=FillBehavior.Stop});}
    catch{presenter.BeginAnimation(UIElement.OpacityProperty,null);}
   });
   return true;
  }catch{st.Swapping=false;st.Pending=null;try{c.Content=value;}catch{}return true;}
 }
 // Collapsible slot (the connection progress line): height and opacity ease instead of jumping.
 internal static bool Reveal(FrameworkElement slot,double height,bool show){
  var st=S(slot);if(st.Active==show)return false;st.Active=show;
  try{
   if(!Enabled||!slot.IsVisible){
    slot.BeginAnimation(FrameworkElement.HeightProperty,null);slot.BeginAnimation(UIElement.OpacityProperty,null);
    slot.Height=show?height:0;slot.Opacity=show?1:0;return true;
   }
   slot.BeginAnimation(FrameworkElement.HeightProperty,new DoubleAnimation(show?height:0,D(show?240:200)){EasingFunction=Out});
   slot.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(show?1:0,D(show?260:160)){EasingFunction=Out});
  }catch{try{slot.BeginAnimation(FrameworkElement.HeightProperty,null);slot.BeginAnimation(UIElement.OpacityProperty,null);slot.Height=show?height:0;slot.Opacity=show?1:0;}catch{}}
  return true;
 }
 // Download progress glides; reports arrive per 80 KB, so animations are started at most every 120 ms.
 internal static void Advance(RangeBase bar,double value){
  try{
   var st=S(bar);long now=Environment.TickCount64;
   if(!Enabled||!bar.IsVisible){bar.BeginAnimation(RangeBase.ValueProperty,null);bar.Value=value;return;}
   if(value<bar.Maximum&&now-st.Stamp<120)return;
   st.Stamp=now;bar.BeginAnimation(RangeBase.ValueProperty,new DoubleAnimation(value,D(180)){EasingFunction=Out});
  }catch{try{bar.BeginAnimation(RangeBase.ValueProperty,null);bar.Value=value;}catch{}}
 }
 internal static void ResetProgress(RangeBase bar,double value=0){
  try{bar.BeginAnimation(RangeBase.ValueProperty,null);bar.Value=value;S(bar).Stamp=0;}catch{}
 }

 // ---- Power mark: spinning arc while connecting, breathing rings while protected ----
 internal static void Spin(UIElement arc,bool on){
  var st=S(arc);if(st.Active==on)return;st.Active=on;
  try{
   var r=RotateOf(arc);
   if(on){
    if(!Enabled){arc.BeginAnimation(UIElement.OpacityProperty,null);arc.Opacity=1;return;}
    arc.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(1,D(200)));
    r.BeginAnimation(RotateTransform.AngleProperty,new DoubleAnimation(0,360,D(1100)){RepeatBehavior=RepeatBehavior.Forever});
    return;
   }
   if(!Enabled){r.BeginAnimation(RotateTransform.AngleProperty,null);arc.BeginAnimation(UIElement.OpacityProperty,null);arc.Opacity=0;return;}
   arc.BeginAnimation(UIElement.OpacityProperty,new DoubleAnimation(0,D(180)));
   After(220,()=>{if(!st.Active)r.BeginAnimation(RotateTransform.AngleProperty,null);});
  }catch{}
 }
 internal static void Breathe(UIElement first,UIElement second,bool on){
  var st=S(first);if(st.Active==on)return;st.Active=on;
  try{
   bool loop=on&&Ambient;int i=0;
   foreach(var ring in new[]{first,second}){
    var s=ScaleOf(ring);
    s.BeginAnimation(ScaleTransform.ScaleXProperty,null);s.BeginAnimation(ScaleTransform.ScaleYProperty,null);ring.BeginAnimation(UIElement.OpacityProperty,null);
    // Without animations a single static halo still marks the protected state.
    bool halo=on&&!loop&&i==0;s.ScaleX=s.ScaleY=halo?1.16:1;ring.Opacity=halo?0.3:0;
    if(loop){
     var begin=TimeSpan.FromMilliseconds(i*1200);
     var grow=new DoubleAnimation(1,1.42,D(2400)){BeginTime=begin,RepeatBehavior=RepeatBehavior.Forever,EasingFunction=Out};
     var fade=new DoubleAnimation(0.55,0,D(2400)){BeginTime=begin,RepeatBehavior=RepeatBehavior.Forever};
     Timeline.SetDesiredFrameRate(grow,30);Timeline.SetDesiredFrameRate(fade,30);
     s.BeginAnimation(ScaleTransform.ScaleXProperty,grow);s.BeginAnimation(ScaleTransform.ScaleYProperty,grow);ring.BeginAnimation(UIElement.OpacityProperty,fade);
    }
    i++;
   }
  }catch{}
 }
 internal static void After(double ms,Action action){
  var timer=new DispatcherTimer(DispatcherPriority.Normal){Interval=TimeSpan.FromMilliseconds(ms)};
  timer.Tick+=(_,_)=>{timer.Stop();try{action();}catch{}};
  timer.Start();
 }
}
