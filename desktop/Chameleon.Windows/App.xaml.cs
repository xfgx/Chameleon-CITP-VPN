using System.Threading;
using System.Windows;
namespace Chameleon.Windows;
public partial class App : Application {
 internal static string? Activation;
 internal static bool Updated;
 internal static event Action? ShowRequested;
 static Mutex? single;static EventWaitHandle? showSignal;
 private void Start(object sender, StartupEventArgs e) {
  // Never echo command-line activation values into errors or logs.
  for(int i=0;i<e.Args.Length-1;i++) if(e.Args[i]=="-activate") Activation=e.Args[i+1];
  Updated=e.Args.Contains("-updated");
  single=new Mutex(true,@"Local\ChameleonVPN.UI.v1",out bool first);
  showSignal=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\ChameleonVPN.UI.Show.v1");
  if(!first){
   // Second launch (shortcut, deep link): store a new key if given, then bring the running window forward.
   if(!string.IsNullOrEmpty(Activation)){try{var c=Vault.Load();Vault.Save(c with{Token=Vault.ParseToken(Activation)});}catch{}}
   showSignal.Set();Shutdown();return;
  }
  ShutdownMode=ShutdownMode.OnExplicitShutdown;
  var signal=showSignal;new Thread(()=>{while(true){try{signal.WaitOne();}catch{return;}ShowRequested?.Invoke();}}){IsBackground=true,Name="show-signal"}.Start();
  var window=new MainWindow(); MainWindow=window; window.Show();
 }
}
