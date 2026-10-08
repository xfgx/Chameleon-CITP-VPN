#!/usr/bin/env python3
"""Source guardrails for the 4.5.1 WPF motion layer (the Linux build node has no Windows runtime)."""
import pathlib,re,unittest,xml.etree.ElementTree as ET
r=pathlib.Path(__file__).resolve().parents[1];w=r/'desktop/Chameleon.Windows'
def read(p):return (w/p).read_text(encoding='utf-8-sig')
class Motion(unittest.TestCase):
 def test_motion_layer(self):
  m=read('Motion.cs')
  for v in ('SystemParameters.ClientAreaAnimation','RegisterClassHandler','FillBehavior.Stop','SetDesiredFrameRate','RepeatBehavior.Forever','ConditionalWeakTable','RenderCapability.Tier'):self.assertIn(v,m)
  self.assertNotIn('Thread.Sleep',m)
 def test_button_template(self):
  a=read('App.xaml');ET.fromstring(a)
  for v in ('x:Name="Root"','x:Name="Glow"','x:Name="Ripples"','x:Name="Presenter"','IsKeyboardFocused'):self.assertIn(v,a)
  # Press feedback is the animated scale + ripple, not an opacity jump.
  self.assertNotIn('IsPressed',a)
 def test_window(self):
  x=read('MainWindow.xaml');c=read('MainWindow.xaml.cs')+read('MainWindow.Motion.cs');app=read('App.xaml.cs')
  for v in ('NavIndicator','NavAccent','PowerSpinner','PowerRingA','PowerRingB','PowerDisc','ProgressSlot'):self.assertIn('x:Name="%s"'%v,x)
  for v in ('IsVisibleChanged','StateChanged','WindowState.Minimized','Motion.SetText(StatusTitle','Motion.Enter(','Motion.Reveal(ProgressSlot'):self.assertIn(v,c)
  self.assertLess(app.index('Motion.Install()'),app.index('new MainWindow()'))
  # State text goes through the idempotent motion helpers (the status refresh repeats every 3 s).
  for v in ('StatusTitle.Text=','StatusDetail.Text=','UpdateTitle.Text=','ConnectButton.Content=','Progress.Visibility='):self.assertIsNone(re.search(r'(?<![A-Za-z0-9_])'+re.escape(v),c),v)
 def test_version(self):
  v=re.search(r'<Version>([0-9]+\.[0-9]+\.[0-9]+)</Version>',read('Chameleon.Windows.csproj')).group(1)
  self.assertIn('Version="%s"'%v,read('Updater.cs'))
  self.assertIn('assemblyIdentity version="%s.0"'%v,read('app.manifest'))
  nsi=(r/'packaging/windows/chameleon.nsi').read_text(encoding='latin-1')
  for s in ('Name "Chameleon VPN %s beta"'%v,'VIProductVersion "%s.0"'%v,'"FileVersion" "%s"'%v,'"DisplayVersion" "%s"'%v):self.assertIn(s,nsi)
  b=(r/'scripts/build-windows-product.sh').read_text(encoding='utf-8')
  self.assertEqual(b.count('Chameleon-%s-windows-setup.exe'%v),2);self.assertIn("'product_version':'%s'"%v,b)
  self.assertTrue((r/'packaging/windows/WINDOWS-README.txt').read_text(encoding='utf-8-sig').startswith('Chameleon VPN %s beta'%v))
  self.assertTrue((r/('docs/releases/WINDOWS-%s.md'%v)).is_file())
if __name__=='__main__':unittest.main()
