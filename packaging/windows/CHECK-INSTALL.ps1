# Read-only diagnostics: no tokens, user vaults, adapters or firewall changes.
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramFiles 'Chameleon VPN'
$service = Get-CimInstance Win32_Service -Filter "Name='ChameleonBroker'"
if (-not $service) { throw 'ChameleonBroker is not installed. Run the new installer and retain its error code.' }
$service | Select-Object Name, State, StartMode, StartName, PathName, ExitCode | Format-List
$expected = '"' + (Join-Path $root 'ChameleonBroker.exe') + '" -broker-service'
if ($service.PathName -ine $expected) { throw 'Unexpected broker ImagePath. Do not manually edit it.' }
if ($service.StartName -ine 'LocalSystem') { throw 'Unexpected broker account.' }
if ($service.State -ne 'Running') { throw 'Broker is not running. Retain the installer error and Event Viewer service error.' }
foreach ($file in @('ChameleonBroker.exe','app\Chameleon.exe','wintun.dll','licenses\WINTUN-LICENSE.txt','licenses\THIRD-PARTY-NOTICES.txt','licenses\CORRESPONDING-SOURCE.txt','licenses\LICENSE-NOTICE.md')) {
  if (-not (Test-Path -LiteralPath (Join-Path $root $file))) { throw "Missing file: $file" }
}
$hash = (Get-FileHash -LiteralPath (Join-Path $root 'wintun.dll') -Algorithm SHA256).Hash
if ($hash -ine 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') { throw 'Wintun integrity mismatch.' }
Write-Host 'PASS: installation layout, service configuration and Wintun integrity. Actual VPN/native-device acceptance is a separate test.'

Get-Service BFE,MpsSvc | Select-Object Name,Status | Format-Table
Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table
Get-Date -Format o
