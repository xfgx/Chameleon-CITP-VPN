using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace Chameleon.Windows;
internal static class AppInfo {internal const string Version="4.5.0";internal const string Channel="beta";}
internal sealed record UpdateInfo(string Version,string File,string Sha256,long Size);
// In-app update: only the fixed official HTTPS site, no redirects. The installer is accepted only if its
// size and SHA-256 match the manifest, the file name and PE version match the manifest version, and the
// version is newer than this build. The file lives in the admin-only Program Files folder and is held open
// with read-only sharing from verification until the installer process has started.
internal static class Updater {
 const string Site="https://vpn.example.com";
 const long MaxInstaller=512L*1024*1024;
 static readonly HttpClient Http=new(new SocketsHttpHandler{AllowAutoRedirect=false,PooledConnectionLifetime=TimeSpan.FromMinutes(5),ConnectTimeout=TimeSpan.FromSeconds(15)}){Timeout=Timeout.InfiniteTimeSpan};
 static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"Chameleon VPN");
 static string Folder=>Path.Combine(Root,"updates");
 internal static bool Installed=>Path.GetFullPath(AppContext.BaseDirectory).TrimEnd('\\').Equals(Path.Combine(Root,"app"),StringComparison.OrdinalIgnoreCase);
 internal static Version Parse(string v)=>Regex.IsMatch(v,@"^\d{1,4}\.\d{1,4}\.\d{1,4}$")?new Version(v):throw new FormatException();
 internal static bool Newer(string candidate)=>Parse(candidate)>Parse(AppInfo.Version);
 static SafeFailure Offline()=>new("update.network","Нет связи с сайтом обновлений. Проверьте интернет и повторите.");
 internal static async Task<UpdateInfo> Check(CancellationToken shutdown){
  using var cts=CancellationTokenSource.CreateLinkedTokenSource(shutdown);cts.CancelAfter(TimeSpan.FromSeconds(20));
  try {
   using var request=new HttpRequestMessage(HttpMethod.Get,Site+"/vpn/manifest.json");request.Headers.CacheControl=new(){NoCache=true};
   using var response=await Http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cts.Token);
   if(!response.IsSuccessStatusCode)throw new SafeFailure("update.manifest","Сайт обновлений ответил кодом "+(int)response.StatusCode+". Повторите позже.");
   await using var stream=await response.Content.ReadAsStreamAsync(cts.Token);
   using var buffer=new MemoryStream();var chunk=new byte[16384];int n;
   while((n=await stream.ReadAsync(chunk,cts.Token))>0){buffer.Write(chunk,0,n);if(buffer.Length>262144)throw new SafeFailure("update.manifest","Слишком большой ответ сайта обновлений.");}
   using var doc=JsonDocument.Parse(buffer.ToArray());
   foreach(var a in doc.RootElement.GetProperty("assets").EnumerateArray()){
    if(a.GetProperty("id").GetString()!="windows")continue;
    var u=new UpdateInfo(a.GetProperty("version").GetString()??"",a.GetProperty("file").GetString()??"",a.GetProperty("sha256").GetString()??"",a.GetProperty("size").GetInt64());
    Parse(u.Version);
    if(u.File!=$"Chameleon-{u.Version}-windows-setup.exe"||!Regex.IsMatch(u.Sha256,"^[0-9a-f]{64}$")||u.Size<1048576||u.Size>MaxInstaller)throw new FormatException();
    return u;
   }
   throw new SafeFailure("update.manifest","На сайте пока нет сборки для Windows.");
  }
  catch(SafeFailure){throw;}
  catch(OperationCanceledException) when(!shutdown.IsCancellationRequested){throw Offline();}
  catch(HttpRequestException){throw Offline();}
  catch(Exception e) when(e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException){throw new SafeFailure("update.manifest","Описание обновления на сайте некорректно. Обновление не будет установлено.");}
 }
 internal static void Cleanup(){try{if(Installed&&Directory.Exists(Folder))foreach(var f in Directory.EnumerateFiles(Folder))try{File.Delete(f);}catch{}}catch{}}
 internal static async Task<string> Download(UpdateInfo u,IProgress<double> progress,CancellationToken shutdown){
  if(!Installed)throw new SafeFailure("update.location","Обновление из приложения работает только для установленной копии в Program Files. Скачайте установщик с сайта.");
  Directory.CreateDirectory(Folder);Cleanup();
  string target=Path.Combine(Folder,u.File),temp=target+".part";
  using var cts=CancellationTokenSource.CreateLinkedTokenSource(shutdown);cts.CancelAfter(TimeSpan.FromMinutes(30));
  try {
   using var response=await Http.GetAsync(Site+"/vpn/download/windows",HttpCompletionOption.ResponseHeadersRead,cts.Token);
   if(!response.IsSuccessStatusCode)throw new SafeFailure("update.download","Сайт обновлений ответил кодом "+(int)response.StatusCode+". Повторите позже.");
   if(response.Content.Headers.ContentLength is long length&&length!=u.Size)throw new SafeFailure("update.size","Размер файла на сайте не совпадает с описанием обновления. Повторите позже.");
   using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);long total=0;
   await using(var stream=await response.Content.ReadAsStreamAsync(cts.Token))
   await using(var file=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None,81920,FileOptions.Asynchronous)){
    var chunk=new byte[81920];int n;
    while((n=await stream.ReadAsync(chunk,cts.Token))>0){
     total+=n;if(total>u.Size)throw new SafeFailure("update.size","Скачанный файл больше ожидаемого. Установка отменена.");
     hash.AppendData(chunk,0,n);await file.WriteAsync(chunk.AsMemory(0,n),cts.Token);progress.Report((double)total/u.Size);
    }
    await file.FlushAsync(cts.Token);
   }
   if(total!=u.Size)throw new SafeFailure("update.size","Загрузка прервалась. Повторите обновление.");
   if(Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant()!=u.Sha256)throw new SafeFailure("update.sha256","Контрольная сумма установщика не совпала. Файл удалён, установка отменена.");
   File.Move(temp,target,true);return target;
  }
  catch(SafeFailure){TryDelete(temp);throw;}
  catch(OperationCanceledException) when(!shutdown.IsCancellationRequested){TryDelete(temp);throw Offline();}
  catch(Exception e) when(e is HttpRequestException or IOException){TryDelete(temp);throw new SafeFailure("update.download","Загрузка обновления не удалась. Проверьте интернет и повторите.");}
  catch{TryDelete(temp);throw;}
 }
 static void TryDelete(string path){try{File.Delete(path);}catch{}}
 // Re-verifies and starts the silent installer. The installer waits for this UI to exit,
 // stops the broker, replaces files, restarts the broker and reopens the app.
 internal static void Launch(UpdateInfo u,string path){
  if(!Installed||!Path.GetDirectoryName(Path.GetFullPath(path))!.Equals(Folder,StringComparison.OrdinalIgnoreCase))throw new SafeFailure("update.location","Недопустимое расположение установщика.");
  using var hold=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
  if(hold.Length!=u.Size||Convert.ToHexString(SHA256.HashData(hold)).ToLowerInvariant()!=u.Sha256)throw new SafeFailure("update.sha256","Контрольная сумма установщика не совпала. Установка отменена.");
  var info=FileVersionInfo.GetVersionInfo(path);
  if(info.ProductName!="Chameleon VPN"||info.FileVersion!=u.Version)throw new SafeFailure("update.version","Версия установщика не совпадает с описанием обновления. Установка отменена.");
  var start=new ProcessStartInfo(path){UseShellExecute=false,WorkingDirectory=Folder};start.ArgumentList.Add("/S");start.ArgumentList.Add("/UPDATE");
  using var process=Process.Start(start)??throw new SafeFailure("update.start","Не удалось запустить установщик.");
 }
}
