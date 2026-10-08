using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;
namespace Chameleon.Windows;
internal sealed record Credentials(
 [property:JsonPropertyName("token")]string Token,
 [property:JsonPropertyName("seed")]string Seed,
 [property:JsonPropertyName("transport_private")]string TransportPrivate);
internal sealed record Reply {
 [JsonPropertyName("version")]public int Version {get;init;}
 [JsonPropertyName("code")]public string? Code {get;init;}
 [JsonPropertyName("state")]public string State {get;init;}="error";
 [JsonPropertyName("message")]public string Message {get;init;}="";
 [JsonPropertyName("mode")]public string? Mode {get;init;}
 [JsonPropertyName("up_bytes")]public ulong Up {get;init;}
 [JsonPropertyName("down_bytes")]public ulong Down {get;init;}
}
internal sealed class SafeFailure(string code,string detail):Exception(detail){public string Code {get;}=code;}
internal static class Vault {
 static readonly string Folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"ChameleonVPN");
 static string FileName=>Path.Combine(Folder,"activation.dpapi");
 static string B64(byte[] b)=>Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');
 internal static Credentials Load() {
  if(!File.Exists(FileName))return new Credentials("",B64(RandomNumberGenerator.GetBytes(32)),B64(RandomNumberGenerator.GetBytes(32)));
  if(new FileInfo(FileName).Length>32768)throw new SafeFailure("vault.invalid","Хранилище ключа повреждено. Оно не будет перезаписано автоматически.");
  byte[] encrypted=File.ReadAllBytes(FileName);if(encrypted.Length>32768)throw new SafeFailure("vault.invalid","Хранилище ключа повреждено. Оно не будет перезаписано автоматически.");
  byte[] plain=ProtectedData.Unprotect(encrypted,null,DataProtectionScope.CurrentUser);
  try {
   var c=JsonSerializer.Deserialize<Credentials>(plain)??throw new CryptographicException();
   if(c.Token.Length>6000 || !Regex.IsMatch(c.Seed,"^[A-Za-z0-9_-]{43}$") || !Regex.IsMatch(c.TransportPrivate,"^[A-Za-z0-9_-]{43}$"))throw new CryptographicException();return c;
  }finally{CryptographicOperations.ZeroMemory(plain);}
 }
 internal static void Save(Credentials c) {
  Directory.CreateDirectory(Folder);byte[] plain=JsonSerializer.SerializeToUtf8Bytes(c);
  try {var encrypted=ProtectedData.Protect(plain,null,DataProtectionScope.CurrentUser);string temp=FileName+"."+Guid.NewGuid().ToString("N")+".tmp";
   try {File.WriteAllBytes(temp,encrypted);File.Move(temp,FileName,true);}finally{if(File.Exists(temp))File.Delete(temp);}
  }finally{CryptographicOperations.ZeroMemory(plain);}
 }
 internal static string ParseToken(string input) {
  if(input.Length>8192)throw new FormatException();string token=input.Trim();
  if(Uri.TryCreate(token,UriKind.Absolute,out var uri)) {
   bool allowed=(uri.Scheme=="chameleon-vpn"&&uri.Host=="activate") || (uri.Scheme=="https"&&uri.Host=="vpn.example.com"&&uri.AbsolutePath=="/vpn/activate"&&uri.IsDefaultPort);
   if(!allowed)throw new FormatException();
   string part=uri.Fragment.TrimStart('#'); if(!part.StartsWith("token=",StringComparison.Ordinal))throw new FormatException();token=Uri.UnescapeDataString(part[6..]);
  }
  if(token.Length>6000||!Regex.IsMatch(token,@"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86}$"))throw new FormatException();return token;
 }
 static string Prefs=>Path.Combine(Folder,"preferences.json");
 static Dictionary<string,JsonElement> ReadPrefs(){try{if(new FileInfo(Prefs).Length>8192)return new();using var d=JsonDocument.Parse(File.ReadAllText(Prefs));var m=new Dictionary<string,JsonElement>(StringComparer.OrdinalIgnoreCase);foreach(var p in d.RootElement.EnumerateObject())m[p.Name]=p.Value.Clone();return m;}catch{return new();}}
 static void WritePrefs(string? protocol=null,bool? consent=null,bool? ruDirect=null){
  var m=ReadPrefs();string current=protocol??(m.TryGetValue("Protocol",out var v)&&v.ValueKind==JsonValueKind.String?v.GetString()??"auto":"auto");
  bool agreed=consent??(m.TryGetValue("SystemConsent",out var c)&&c.ValueKind==JsonValueKind.True);
  bool direct=ruDirect??!(m.TryGetValue("RuDirect",out var r)&&r.ValueKind==JsonValueKind.False);
  Directory.CreateDirectory(Folder);string temp=Prefs+"."+Guid.NewGuid().ToString("N")+".tmp";
  try{File.WriteAllText(temp,JsonSerializer.Serialize(new {Protocol=current,SystemConsent=agreed,RuDirect=direct}));File.Move(temp,Prefs,true);}finally{if(File.Exists(temp))File.Delete(temp);}
 }
 // No saved choice means AUTO. Explicit CITP/KS choices from 4.3/4.4 are kept.
 internal static string Protocol(){var m=ReadPrefs();if(m.TryGetValue("Protocol",out var v)&&v.ValueKind==JsonValueKind.String){var s=v.GetString();if(s is "citp" or "ks" or "auto")return s;}return "auto";}
 internal static void Protocol(string value){if(value is not ("citp" or "ks" or "auto"))throw new ArgumentException();WritePrefs(protocol:value);}
 internal static bool SystemConsent(){var m=ReadPrefs();return m.TryGetValue("SystemConsent",out var v)&&v.ValueKind==JsonValueKind.True;}
 internal static void SystemConsent(bool value)=>WritePrefs(consent:value);
 // "Российские сайты напрямую" (docs/RU-DIRECT.md). On unless the user switched it off.
 internal static bool RuDirect(){var m=ReadPrefs();return !(m.TryGetValue("RuDirect",out var v)&&v.ValueKind==JsonValueKind.False);}
 internal static void RuDirect(bool value)=>WritePrefs(ruDirect:value);
}
internal sealed record PrepResult(bool Ok,string Code,string Detail,string Summary);
// Starts only fixed, required Windows services. Never disables security features or touches other programs.
internal static class SystemPrep {
 const uint Connect=1,QueryStatus=4,Start=0x10,QueryConfig=1,ChangeConfig=2;
 internal static PrepResult Ensure(){
  var parts=new List<string>();string? failCode=null,failDetail=null;
  foreach(var (name,label,own) in new[]{("BFE","BFE",false),("MpsSvc","Firewall",false),("ChameleonBroker","Broker",true)}){
   var (ok,state)=EnsureRunning(name,own);parts.Add(label+": "+state);
   if(!ok&&failCode==null){failCode="system."+name.ToLowerInvariant();failDetail=own?"Служба ChameleonBroker не запущена ("+state+"). Переустановите приложение установщиком.":"Служба Windows «"+name+"» не запущена ("+state+"). Она нужна для защитных правил VPN. Включите её в «Службах» Windows или через политику организации.";}
  }
  string wintun=File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Chameleon VPN","wintun.dll"))?"есть":"нет";parts.Add("Wintun: "+wintun);
  if(wintun=="нет"&&failCode==null){failCode="system.wintun";failDetail="Не найден wintun.dll. Переустановите приложение установщиком.";}
  return new PrepResult(failCode==null,failCode??"",failDetail??"",string.Join(" · ",parts));
 }
 static (bool,string) EnsureRunning(string name,bool own){
  nint scm=OpenSCManagerW(null,null,Connect);if(scm==0)return(false,"SCM "+Marshal.GetLastWin32Error());
  try{
   nint svc=OpenServiceW(scm,name,QueryStatus|Start|QueryConfig|(own?ChangeConfig:0));
   if(svc==0){int err=Marshal.GetLastWin32Error();return(false,err==1060?"не установлена":"ошибка "+err);}
   try{
    if(!QueryServiceStatusEx(svc,0,out var st,(uint)Marshal.SizeOf<ServiceStatus>(),out _))return(false,"статус "+Marshal.GetLastWin32Error());
    if(st.State==4)return(true,"работает");
    if(own)ChangeServiceConfigW(svc,0xFFFFFFFF,2,0xFFFFFFFF,null,null,0,null,null,null,null); // our broker: automatic start
    if(!StartServiceW(svc,0,0)){int err=Marshal.GetLastWin32Error();if(err!=1056)return(false,err==1058?"отключена":"запуск "+err);}
    for(int i=0;i<40;i++){Thread.Sleep(250);if(QueryServiceStatusEx(svc,0,out st,(uint)Marshal.SizeOf<ServiceStatus>(),out _)&&st.State==4)return(true,"запущена");}
    return(false,"не запустилась");
   }finally{CloseServiceHandle(svc);}
  }finally{CloseServiceHandle(scm);}
 }
 [StructLayout(LayoutKind.Sequential)]struct ServiceStatus{public uint Type,State,Accepted,Win32Exit,SpecificExit,Checkpoint,WaitHint,PID,Flags;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern nint OpenSCManagerW(string? machine,string? db,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern nint OpenServiceW(nint scm,string name,uint access);
 [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool QueryServiceStatusEx(nint h,int level,out ServiceStatus status,uint size,out uint needed);
 [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool StartServiceW(nint h,uint argc,nint argv);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool ChangeServiceConfigW(nint h,uint type,uint start,uint error,string? path,string? group,nint tag,string? deps,string? user,string? password,string? display);
 [DllImport("advapi32.dll")][return:MarshalAs(UnmanagedType.Bool)]static extern bool CloseServiceHandle(nint h);
}
internal static class BrokerClient {
 static readonly JsonSerializerOptions Strict=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
 internal static async Task<Reply> Call(string command,string protocol,Credentials? credentials=null,CancellationToken shutdown=default,bool? ruDirect=null) {
  using var deadline=CancellationTokenSource.CreateLinkedTokenSource(shutdown);deadline.CancelAfter(command=="connect"?TimeSpan.FromSeconds(protocol=="auto"?150:85):TimeSpan.FromSeconds(10));var ct=deadline.Token;
  using var pipe=new NamedPipeClientStream(".","ChameleonFreeVPN.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
  string stage="open";
  try {
   await pipe.ConnectAsync(4000,ct);stage="server_identity";Verify(pipe.SafePipeHandle);
   stage="send";byte[] body=JsonSerializer.SerializeToUtf8Bytes(new {version=1,command,protocol,credentials,ru_direct=ruDirect},new JsonSerializerOptions {DefaultIgnoreCondition=JsonIgnoreCondition.WhenWritingNull});
   if(body.Length>16384)throw new SafeFailure("ipc.frame","Недопустимый размер запроса.");
   try {byte[] length=new byte[4];BinaryPrimitives.WriteUInt32LittleEndian(length,(uint)body.Length);await pipe.WriteAsync(length,ct);await pipe.WriteAsync(body,ct);await pipe.FlushAsync(ct);}finally{CryptographicOperations.ZeroMemory(body);}
   stage="receive";byte[] header=new byte[4];await pipe.ReadExactlyAsync(header,ct);uint size=BinaryPrimitives.ReadUInt32LittleEndian(header);if(size<2||size>16384)throw new SafeFailure("ipc.frame","Служба вернула некорректный размер ответа.");
   byte[] answer=new byte[size];await pipe.ReadExactlyAsync(answer,ct);var r=JsonSerializer.Deserialize<Reply>(answer,Strict);
   if(r==null||r.Version!=1||r.Message.Length>4096||r.Code?.Length>128||!new[]{"disconnected","connecting","connected","reconnecting","disconnecting","error"}.Contains(r.State))throw new SafeFailure("ipc.protocol","Версия или структура ответа службы не поддерживается.");return r;
  }catch(SafeFailure){throw;}catch(OperationCanceledException){throw new SafeFailure("ipc."+stage,"Превышено время ожидания службы. Повторите проверку.");}
  catch(Exception e) when(e is IOException or TimeoutException or JsonException or System.ComponentModel.Win32Exception){throw new SafeFailure("ipc."+stage,"Ошибка обмена со службой. Восстановите установку и повторите проверку.");}
 }
 static void Need(bool okay,string stage){if(!okay)throw new SafeFailure("ipc.server_identity","Не подтверждена служба Chameleon: "+stage+". Восстановите установку, не запускайте копию EXE.");}
 static void Verify(SafePipeHandle pipe) {
  string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Chameleon VPN");
  Need(Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(Path.Combine(root,"app"),StringComparison.OrdinalIgnoreCase),"каталог приложения");
  Need(GetNamedPipeServerProcessId(pipe,out uint pid)&&pid!=0,"PID канала");
  nint scm=OpenSCManagerW(null,null,1);Need(scm!=0,"SCM");
  try {nint service=OpenServiceW(scm,"ChameleonBroker",4);Need(service!=0,"регистрация службы");
   try {Need(QueryServiceStatusEx(service,0,out var st,(uint)Marshal.SizeOf<ServiceStatus>(),out _)&&st.PID==pid&&st.State==4,"PID службы");}finally{CloseServiceHandle(service);}
  }finally{CloseServiceHandle(scm);}
  using var process=OpenProcess(0x1000,false,pid);Need(!process.IsInvalid,"доступ к процессу (Win32 "+Marshal.GetLastWin32Error()+")");var name=new StringBuilder(32768);uint len=(uint)name.Capacity;
  Need(QueryFullProcessImageNameW(process,0,name,ref len),"путь процесса");Need(name.ToString().Equals(Path.Combine(root,"ChameleonBroker.exe"),StringComparison.OrdinalIgnoreCase),"установленный брокер");
 }
 [StructLayout(LayoutKind.Sequential)]struct ServiceStatus{public uint Type,State,Accepted,Win32Exit,SpecificExit,Checkpoint,WaitHint,PID,Flags;}
 [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool GetNamedPipeServerProcessId(SafePipeHandle h,out uint pid);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern nint OpenSCManagerW(string? machine,string? db,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern nint OpenServiceW(nint scm,string name,uint access);
 [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool QueryServiceStatusEx(nint h,int level,out ServiceStatus status,uint size,out uint needed);
 [DllImport("advapi32.dll")][return:MarshalAs(UnmanagedType.Bool)]static extern bool CloseServiceHandle(nint h);
 [DllImport("kernel32.dll",SetLastError=true)]static extern SafeProcessHandle OpenProcess(uint access,[MarshalAs(UnmanagedType.Bool)]bool inherit,uint pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]static extern bool QueryFullProcessImageNameW(SafeProcessHandle h,uint flags,StringBuilder value,ref uint length);
}
