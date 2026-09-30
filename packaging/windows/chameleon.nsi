Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
Var UpdateMode
!ifndef BUILD_DIR
!error "BUILD_DIR must point to the verified build-host build directory"
!endif
!ifndef OUTPUT
!error "OUTPUT is required"
!endif
Name "Chameleon VPN 4.5.0 beta"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\Chameleon VPN"
InstallDirRegKey HKLM "Software\ChameleonFreeVPN" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUninstDetails show
!define MUI_ABORTWARNING
!define MUI_ICON "${BUILD_DIR}/chameleon.ico"
!define MUI_UNICON "${BUILD_DIR}/chameleon.ico"
VIProductVersion "4.5.0.0"
VIAddVersionKey /LANG=1033 "ProductName" "Chameleon VPN"
VIAddVersionKey /LANG=1033 "FileDescription" "Chameleon VPN installer"
VIAddVersionKey /LANG=1033 "FileVersion" "4.5.0"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Chameleon project"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${BUILD_DIR}/THIRD-PARTY-NOTICES.txt"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "Chameleon requires Windows x64."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  ; "/S /UPDATE" is used only by the in-app updater of an already installed copy.
  StrCpy $UpdateMode 0
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/UPDATE" $R1
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "Chameleon VPN"
  ; The broker and its DLL must never be placed in a user-writable directory.
  StrCpy $INSTDIR "$PROGRAMFILES64\Chameleon VPN"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=broker-setup.exe "${BUILD_DIR}/broker-setup.exe"
  ${If} $UpdateMode == 1
  ${AndIf} ${FileExists} "$INSTDIR\app\Chameleon.exe"
    ; Wait (max 30 s) until the updating UI has exited and released app\Chameleon.exe.
    StrCpy $R2 0
    update_wait:
    ClearErrors
    FileOpen $R3 "$INSTDIR\app\Chameleon.exe" a
    IfErrors 0 update_ready
    IntOp $R2 $R2 + 1
    IntCmp $R2 60 update_timeout 0 update_timeout
    Sleep 500
    Goto update_wait
    update_ready:
    FileClose $R3
    update_timeout:
  ${EndIf}
  ; A native x64 helper avoids sc.exe WOW64 redirection and nested binPath quotes.
  nsExec::ExecToStack /TIMEOUT=60000 '"$PLUGINSDIR\broker-setup.exe" -action stop'
  Pop $2
  Pop $3
  DetailPrint "$3"
  ${If} $2 != 0
    MessageBox MB_ICONSTOP "Не удалось остановить службу Chameleon (код $2).$\r$\n$3$\r$\nЗакройте приложение и повторите установку."
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR"
  File "${BUILD_DIR}/ChameleonBroker.exe"
  SetOutPath "$INSTDIR\app"
  File /r "${BUILD_DIR}/app/*"
  SetOutPath "$INSTDIR"
  File "${BUILD_DIR}/wintun.dll"
  SetOutPath "$INSTDIR\tools"
  File "${BUILD_DIR}/broker-setup.exe"
  File "${BUILD_DIR}/CHECK-INSTALL.ps1"
  File "${BUILD_DIR}/IPC-SELFTEST.exe"
  SetOutPath "$INSTDIR\licenses"
  File "${BUILD_DIR}/WINTUN-LICENSE.txt"
  File "${BUILD_DIR}/DOTNET-LICENSE.txt"
  File "${BUILD_DIR}/DOTNET-THIRD-PARTY-NOTICES.txt"
  File "${BUILD_DIR}/THIRD-PARTY-NOTICES.txt"
  File "${BUILD_DIR}/CORRESPONDING-SOURCE.txt"
  File /oname=MIT-LICENSE.txt "../../LICENSE"
  File /oname=LICENSE-NOTICE.md "../../LICENSE-NOTICE.md"
  SetOutPath "$INSTDIR\docs"
  File "${BUILD_DIR}/WINDOWS-README.txt"
  ; Clean only the named notices left by the old installer.
  Delete "$INSTDIR\WINTUN-LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\CORRESPONDING-SOURCE.txt"
  nsExec::ExecToStack /TIMEOUT=60000 '"$PLUGINSDIR\broker-setup.exe" -action install'
  Pop $2
  Pop $3
  DetailPrint "$3"
  ${If} $2 != 0
    MessageBox MB_ICONSTOP "Не удалось зарегистрировать службу Chameleon (код $2).$\r$\n$3$\r$\nVPN не запускался."
    Abort
  ${EndIf}
  ; Remove the unused legacy GUI only after service migration succeeded.
  Delete "$INSTDIR\Chameleon.exe"
  WriteRegStr HKLM "Software\ChameleonFreeVPN" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Classes\chameleon-vpn" "" "Chameleon activation"
  WriteRegStr HKLM "Software\Classes\chameleon-vpn" "URL Protocol" ""
  WriteRegStr HKLM "Software\Classes\chameleon-vpn\shell\open\command" "" '"$INSTDIR\app\Chameleon.exe" -activate "%1"'
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "DisplayName" "Chameleon VPN 4.5.0 beta"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "DisplayVersion" "4.5.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "DisplayIcon" "$INSTDIR\app\Chameleon.exe,0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "Publisher" "Chameleon project"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN" "NoRepair" 1
  SetOutPath "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\Chameleon VPN"
  CreateShortcut "$SMPROGRAMS\Chameleon VPN\Chameleon VPN.lnk" "$INSTDIR\app\Chameleon.exe" ""
  CreateShortcut "$DESKTOP\Chameleon VPN.lnk" "$INSTDIR\app\Chameleon.exe" ""
  nsExec::ExecToStack /TIMEOUT=60000 '"$PLUGINSDIR\broker-setup.exe" -action start'
  Pop $2
  Pop $3
  DetailPrint "$3"
  ${If} $2 != 0
    MessageBox MB_ICONEXCLAMATION "Файлы установлены, но служба не запустилась (код $2).$\r$\n$3$\r$\nДиагностика: tools\CHECK-INSTALL.ps1"
    SetErrorLevel 2
  ${EndIf}
  ; Manual install: do not launch the GUI as the elevated installer account.
  ; In-app update: the installer was started by the user's own running app, so reopen it.
  ${If} $UpdateMode == 1
    Exec '"$INSTDIR\app\Chameleon.exe" -updated'
  ${EndIf}
SectionEnd

Section "Uninstall"
  InitPluginsDir
  CopyFiles /SILENT "$INSTDIR\tools\broker-setup.exe" "$PLUGINSDIR\broker-setup.exe"
  nsExec::ExecToStack /TIMEOUT=60000 '"$PLUGINSDIR\broker-setup.exe" -action remove'
  Pop $0
  Pop $1
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Служба не удалена (код $0).$\r$\n$1$\r$\nФайлы сохранены; закройте приложение и повторите удаление."
    Abort
  ${EndIf}
  ${DisableX64FSRedirection}
  ; These are only our own named rules. Never remove another VPN's adapters/drivers.
  nsExec::ExecToStack '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name=ChameleonFree-IPv6'
  Pop $0
  Pop $1
  nsExec::ExecToStack '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name=ChameleonFree-DNS-TCP'
  Pop $0
  Pop $1
  nsExec::ExecToStack '"$SYSDIR\netsh.exe" advfirewall firewall delete rule name=ChameleonFree-DNS-UDP'
  Pop $0
  Pop $1
  ${EnableX64FSRedirection}
  Delete "$DESKTOP\Chameleon VPN.lnk"
  Delete "$SMPROGRAMS\Chameleon VPN\Chameleon VPN.lnk"
  RMDir "$SMPROGRAMS\Chameleon VPN"
  DeleteRegKey HKLM "Software\Classes\chameleon-vpn"
  DeleteRegKey HKLM "Software\ChameleonFreeVPN"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ChameleonFreeVPN"
  Delete "$INSTDIR\Chameleon.exe"
  Delete "$INSTDIR\ChameleonBroker.exe"
  RMDir /r "$INSTDIR\app"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\WINTUN-LICENSE.txt"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\CORRESPONDING-SOURCE.txt"
  Delete "$INSTDIR\licenses\WINTUN-LICENSE.txt"
  Delete "$INSTDIR\licenses\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\licenses\CORRESPONDING-SOURCE.txt"
  Delete "$INSTDIR\licenses\LICENSE-NOTICE.md"
  Delete "$INSTDIR\licenses\MIT-LICENSE.txt"
  Delete "$INSTDIR\licenses\DOTNET-LICENSE.txt"
  Delete "$INSTDIR\licenses\DOTNET-THIRD-PARTY-NOTICES.txt"
  RMDir "$INSTDIR\licenses"
  Delete "$INSTDIR\docs\WINDOWS-README.txt"
  RMDir "$INSTDIR\docs"
  Delete "$INSTDIR\tools\broker-setup.exe"
  Delete "$INSTDIR\tools\CHECK-INSTALL.ps1"
  Delete "$INSTDIR\tools\IPC-SELFTEST.exe"
  RMDir "$INSTDIR\tools"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir /r "$INSTDIR\updates"
  RMDir "$INSTDIR"
  ; DPAPI-protected identity in each user's LocalAppData is deliberately retained.
SectionEnd
