//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Fixed script, no interpolation from users, profiles, node addresses or secrets.
// Uses Windows Firewall COM, not localized netsh address-range parsing.
const guardsScript = `$ErrorActionPreference='Stop'; $stage='service'
try {
 foreach($n in @('BFE','MpsSvc')) { if((Get-Service -Name $n).Status -ne 'Running'){[Console]::WriteLine('FAIL:service:0');exit 21} }
 $stage='policy'; $p=New-Object -ComObject HNetCfg.FwPolicy2
 if($p.LocalPolicyModifyState -ne 0){[Console]::WriteLine('FAIL:policy:0');exit 24}
 $current=$p.CurrentProfileTypes
 foreach($f in @(1,2,4)){if(($current -band $f) -ne 0 -and -not $p.FirewallEnabled($f)){[Console]::WriteLine('FAIL:disabled:0');exit 22}}
 foreach($name in @('ChameleonFree-IPv6','ChameleonFree-DNS-TCP','ChameleonFree-DNS-UDP')){try{$p.Rules.Remove($name)}catch{};try{Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue}catch{}}
 $v4='0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255'
 $specs=@(
 @('ChameleonFree-IPv6',256,@('::/1,8000::/1','::-7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,8000::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),''),
 @('ChameleonFree-DNS-TCP',6,@($v4,'0.0.0.0/2,64.0.0.0/3,96.0.0.0/4,112.0.0.0/5,120.0.0.0/6,124.0.0.0/7,126.0.0.0/8,128.0.0.0/1'),'53'),
 @('ChameleonFree-DNS-UDP',17,@($v4,'0.0.0.0/2,64.0.0.0/3,96.0.0.0/4,112.0.0.0/5,120.0.0.0/6,124.0.0.0/7,126.0.0.0/8,128.0.0.0/1'),'53'))
 foreach($s in $specs){$stage=$s[0];$done=$false;$last=$null
  foreach($addr in $s[2]){
   try{try{$p.Rules.Remove($s[0])}catch{}
    $r=New-Object -ComObject HNetCfg.FWRule;$r.Name=$s[0];$r.Description='Chameleon VPN privacy guard';$r.Protocol=[int]$s[1];if($s[3]){$r.RemotePorts=$s[3]};$r.RemoteAddresses=$addr;$r.Direction=2;$r.Action=0;$r.Profiles=2147483647;$r.InterfaceTypes='All';$r.Enabled=$true;$p.Rules.Add($r)
    $v=$p.Rules.Item($s[0]);if(-not $v.Enabled -or $v.Action -ne 0 -or $v.Direction -ne 2 -or $v.RemoteAddresses -eq '*'){throw 'verification'};$done=$true;break
   }catch{$last=$_}
  }
  if(-not $done){
   try{try{$p.Rules.Remove($s[0])}catch{};$pr=@{256='Any';6='TCP';17='UDP'}[[int]$s[1]]
    $a=@{Name=$s[0];DisplayName=$s[0];Description='Chameleon VPN privacy guard';Direction='Outbound';Action='Block';Protocol=$pr;RemoteAddress=($s[2][0] -split ',');Profile='Any';Enabled='True';ErrorAction='Stop'}
    if($s[3]){$a.RemotePort=$s[3]};New-NetFirewallRule @a | Out-Null
    $v=$p.Rules.Item($s[0]);if(-not $v.Enabled -or $v.Action -ne 0 -or $v.Direction -ne 2 -or $v.RemoteAddresses -eq '*'){throw 'verification'};$done=$true
   }catch{if($last){throw $last};throw}
  }
 }
 [Console]::WriteLine('OK')
} catch {[Console]::WriteLine(('FAIL:{0}:{1}' -f $stage,$_.Exception.HResult));exit 23}`
const removeGuardsScript = `$ErrorActionPreference='Stop';try{$p=New-Object -ComObject HNetCfg.FwPolicy2;foreach($n in @('ChameleonFree-IPv6','ChameleonFree-DNS-TCP','ChameleonFree-DNS-UDP')){try{$p.Rules.Remove($n)}catch{}}}catch{} `

func powershellGuards(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	root := os.Getenv("SystemRoot")
	if root == "" {
		return "", errors.New("Windows directory unavailable")
	}
	cmd := exec.CommandContext(ctx, filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	b, e := cmd.Output()
	if len(b) > 4096 {
		return "", errors.New("invalid guard result")
	}
	return strings.TrimSpace(string(b)), e
}
func removeProductGuards() { _, _ = powershellGuards(removeGuardsScript) }
func addProductGuards() error {
	out, e := powershellGuards(guardsScript)
	if e == nil && out == "OK" {
		return nil
	}
	removeProductGuards()
	match := regexp.MustCompile(`^FAIL:(service|disabled|policy|ChameleonFree-IPv6|ChameleonFree-DNS-TCP|ChameleonFree-DNS-UDP):(-?[0-9]{1,11})$`).FindStringSubmatch(out)
	if match != nil {
		return &guardFailure{match[1], match[2]}
	}
	return &guardFailure{"engine", "0"}
}
