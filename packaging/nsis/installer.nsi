Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!include "WordFunc.nsh"

!ifndef VERSION
  !error "VERSION required"
!endif
!ifndef PAYLOAD
  !error "PAYLOAD required"
!endif
!ifndef OUTPUT
  !error "OUTPUT required"
!endif
!define PRODUCT "安信代码签名证书工具"
!define COMPANY "安徽斯百德信息技术有限公司"
!ifdef AUTOMATED_TEST
  RequestExecutionLevel user
  !define HIVE HKCU
  !define REGKEY "Software\AnxinCodeSigner-InstallerQA\Uninstall"
  !define MUTEX "Local\AnxinCodeSigner-InstallerQA"
!else
  RequestExecutionLevel admin
  !define HIVE HKLM
  !define REGKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\AnxinCodeSigner"
  !define MUTEX "Global\AnxinCodeSigner-Installer"
!endif

Name "${PRODUCT}"
OutFile "${OUTPUT}"
BrandingText "${COMPANY}"
SetCompressor /SOLID lzma
SetCompressorDictSize 32
VIProductVersion "${VERSION}.0"
VIAddVersionKey /LANG=2052 "ProductName" "${PRODUCT}"
VIAddVersionKey /LANG=2052 "CompanyName" "${COMPANY}"
VIAddVersionKey /LANG=2052 "FileDescription" "${PRODUCT}安装程序"
VIAddVersionKey /LANG=2052 "FileVersion" "${VERSION}.0"
VIAddVersionKey /LANG=2052 "LegalCopyright" "Copyright (C) 2026 ${COMPANY}"
!define MUI_ICON "..\..\src\CodeSigner.App\Assets\CodeSigner.ico"
!define MUI_UNICON "..\..\src\CodeSigner.App\Assets\CodeSigner.ico"
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"

Var Repair
Var MutexHandle
Var Parameters
Var ExistingVersion

!macro CheckOwnedPath RELATIVE
  System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR\${RELATIVE}") i .r1'
  ${If} $1 != -1
    IntOp $1 $1 & 0x400
    ${If} $1 != 0
      SetErrorLevel 30
      Quit
    ${EndIf}
  ${EndIf}
!macroend

!macro CheckOwnedFiles
  !insertmacro CheckOwnedPath "CodeSigner.App.exe"
  !insertmacro CheckOwnedPath "CodeSigner.App.exe.new"
  !insertmacro CheckOwnedPath "CodeSigner.App.exe.previous"
  !insertmacro CheckOwnedPath "CodeSigner.Worker.exe"
  !insertmacro CheckOwnedPath "CodeSigner.Worker.exe.new"
  !insertmacro CheckOwnedPath "CodeSigner.Worker.exe.previous"
  !insertmacro CheckOwnedPath "Maintenance"
  !insertmacro CheckOwnedPath "Maintenance\Setup.exe"
  !insertmacro CheckOwnedPath "Uninstall.exe"
  !insertmacro CheckOwnedPath "LICENSE"
  !insertmacro CheckOwnedPath "NOTICE"
  !insertmacro CheckOwnedPath "THIRD-PARTY-NOTICES.txt"
  !insertmacro CheckOwnedPath "source-manifest.json"
!macroend

!macro FixedDirectory
  !ifdef AUTOMATED_TEST
    StrCpy $INSTDIR "$LOCALAPPDATA\AnxinCodeSigner-InstallerQA"
    SetShellVarContext current
  !else
    StrCpy $INSTDIR "$PROGRAMFILES64\AnxinCodeSigner"
    SetShellVarContext all
  !endif
!macroend

!macro AcquireMutex
  System::Call 'kernel32::CreateMutexW(p 0, i 0, w "${MUTEX}") p .r0 ?e'
  Pop $1
  StrCpy $MutexHandle $0
  ${If} $0 == 0
  ${OrIf} $1 == 183
    SetErrorLevel 10
    Quit
  ${EndIf}
!macroend

; Fail closed on redirected installation roots before writes or deletion.
!macro CheckDirectory
  StrCpy $0 $INSTDIR
  ${Do}
    System::Call 'kernel32::GetFileAttributesW(w r0) i .r1'
    ${If} $1 != -1
      IntOp $1 $1 & 0x400
      ${If} $1 != 0
        MessageBox MB_ICONSTOP "安装目录不能是链接或重定向目录。" /SD IDOK
        SetErrorLevel 30
        Quit
      ${EndIf}
    ${EndIf}
    ${GetParent} "$0" $1
    ${If} $1 == $0
    ${OrIf} $1 == ""
      ${ExitDo}
    ${EndIf}
    StrCpy $0 $1
  ${Loop}
!macroend

Function .onInit
  SetRegView 64
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "本程序需要 Windows x64。" /SD IDOK
    SetErrorLevel 30
    Quit
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "本程序需要 Windows 10 或更高版本。" /SD IDOK
    SetErrorLevel 30
    Quit
  ${EndIf}
  !insertmacro FixedDirectory
  !insertmacro CheckDirectory
  !insertmacro CheckOwnedFiles
  !insertmacro AcquireMutex
  ${GetParameters} $Parameters
  StrCpy $Repair "0"
  ClearErrors
  ${GetOptions} "$Parameters" "/REPAIR" $0
  ${IfNot} ${Errors}
    StrCpy $Repair "1"
    ReadRegStr $0 ${HIVE} "${REGKEY}" "InstallLocation"
    ReadRegStr $1 ${HIVE} "${REGKEY}" "DisplayVersion"
    ${If} $0 != $INSTDIR
    ${OrIf} $1 != "${VERSION}"
      SetErrorLevel 30
      Quit
    ${EndIf}
  ${EndIf}
  ReadRegStr $ExistingVersion ${HIVE} "${REGKEY}" "DisplayVersion"
  ${If} $ExistingVersion != ""
    ${VersionCompare} "$ExistingVersion" "${VERSION}" $0
    ${If} $0 == 1
      MessageBox MB_ICONSTOP "已安装更新版本，请使用对应版本的安装包。" /SD IDOK
      SetErrorLevel 30
      Quit
    ${EndIf}
  ${EndIf}
    ; Only the external lookup is substituted in QA. The migration branch is shared.
    Call DetectLegacyMsi
    ${If} $1 == 0
      MessageBox MB_ICONINFORMATION "检测到旧版 MSI 安装。请先关闭工具，在 Windows 设置中卸载旧版安信证书签名工具，再运行本安装包。您的证书、原文件和签名输出无需删除。" /SD IDOK
      SetErrorLevel 20
      Quit
    ${ElseIf} $1 != 259
      MessageBox MB_ICONSTOP "无法确认旧版安装状态，请稍后重试。" /SD IDOK
      SetErrorLevel 30
      Quit
    ${EndIf}
FunctionEnd

Function DetectLegacyMsi
  !ifdef AUTOMATED_TEST
    ClearErrors
    ReadRegDWORD $1 ${HIVE} "${REGKEY}" "LegacyMsiStatus"
    ${If} ${Errors}
      StrCpy $1 259
    ${EndIf}
  !else
    System::Call 'msi::MsiEnumRelatedProductsW(w "{C81BF087-67D0-41F3-8581-9E773813118B}", i 0, i 0, w .r0) i .r1'
  !endif
FunctionEnd

; Reject locked executable files; never terminate the user's running processes.
Function CheckExecutable
  Exch $0
  IfFileExists "$0" 0 unlock_done
  System::Call 'kernel32::CreateFileW(w r0, i 0xC0000000, i 0, p 0, i 3, i 0, p 0) p .r1'
  ${If} $1 == -1
    MessageBox MB_ICONEXCLAMATION "程序或签名组件正在使用中，请关闭工具后重试。" /SD IDOK
    SetErrorLevel 10
    Quit
  ${EndIf}
  System::Call 'kernel32::CloseHandle(p r1)'
  unlock_done:
  Pop $0
FunctionEnd

Section "安装"
  ${If} $Repair != "1"
    Push "$INSTDIR\CodeSigner.App.exe"
    Call CheckExecutable
  ${EndIf}
  Push "$INSTDIR\CodeSigner.Worker.exe"
  Call CheckExecutable
  InitPluginsDir
  SetOutPath "$PLUGINSDIR\payload"
  ClearErrors
  File "${PAYLOAD}\CodeSigner.App.exe"
  File "${PAYLOAD}\CodeSigner.Worker.exe"
  File "${PAYLOAD}\LICENSE"
  File "${PAYLOAD}\NOTICE"
  File "${PAYLOAD}\THIRD-PARTY-NOTICES.txt"
  File "${PAYLOAD}\source-manifest.json"
  ${If} ${Errors}
    SetErrorLevel 20
    Quit
  ${EndIf}
  CreateDirectory "$INSTDIR"
  ; Keep the existing Worker until the replacement is fully written.
  ClearErrors
  CopyFiles /SILENT "$PLUGINSDIR\payload\CodeSigner.Worker.exe" "$INSTDIR\CodeSigner.Worker.exe.new"
  ${If} ${Errors}
    SetErrorLevel 20
    Quit
  ${EndIf}
  Delete "$INSTDIR\CodeSigner.Worker.exe.previous"
  IfFileExists "$INSTDIR\CodeSigner.Worker.exe" 0 +2
    Rename "$INSTDIR\CodeSigner.Worker.exe" "$INSTDIR\CodeSigner.Worker.exe.previous"
  ClearErrors
  Rename "$INSTDIR\CodeSigner.Worker.exe.new" "$INSTDIR\CodeSigner.Worker.exe"
  ${If} ${Errors}
    Rename "$INSTDIR\CodeSigner.Worker.exe.previous" "$INSTDIR\CodeSigner.Worker.exe"
    SetErrorLevel 20
    Quit
  ${EndIf}
  ${If} $Repair == "1"
    Delete "$INSTDIR\CodeSigner.Worker.exe.previous"
    SetErrorLevel 0
    Goto install_done
  ${EndIf}
  ClearErrors
  CopyFiles /SILENT "$PLUGINSDIR\payload\CodeSigner.App.exe" "$INSTDIR\CodeSigner.App.exe.new"
  ${If} ${Errors}
    Delete "$INSTDIR\CodeSigner.Worker.exe"
    Rename "$INSTDIR\CodeSigner.Worker.exe.previous" "$INSTDIR\CodeSigner.Worker.exe"
    SetErrorLevel 20
    Quit
  ${EndIf}
  Delete "$INSTDIR\CodeSigner.App.exe.previous"
  IfFileExists "$INSTDIR\CodeSigner.App.exe" 0 +2
    Rename "$INSTDIR\CodeSigner.App.exe" "$INSTDIR\CodeSigner.App.exe.previous"
  ClearErrors
  Rename "$INSTDIR\CodeSigner.App.exe.new" "$INSTDIR\CodeSigner.App.exe"
  ${If} ${Errors}
    Rename "$INSTDIR\CodeSigner.App.exe.previous" "$INSTDIR\CodeSigner.App.exe"
    Delete "$INSTDIR\CodeSigner.Worker.exe"
    Rename "$INSTDIR\CodeSigner.Worker.exe.previous" "$INSTDIR\CodeSigner.Worker.exe"
    SetErrorLevel 20
    Quit
  ${EndIf}
  ClearErrors
  CopyFiles /SILENT "$PLUGINSDIR\payload\LICENSE" "$INSTDIR\LICENSE"
  CopyFiles /SILENT "$PLUGINSDIR\payload\NOTICE" "$INSTDIR\NOTICE"
  CopyFiles /SILENT "$PLUGINSDIR\payload\THIRD-PARTY-NOTICES.txt" "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  CopyFiles /SILENT "$PLUGINSDIR\payload\source-manifest.json" "$INSTDIR\source-manifest.json"
  CreateDirectory "$INSTDIR\Maintenance"
  ${If} $EXEPATH != "$INSTDIR\Maintenance\Setup.exe"
    CopyFiles /SILENT "$EXEPATH" "$INSTDIR\Maintenance\Setup.exe"
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  ${If} ${Errors}
    MessageBox MB_ICONSTOP "安装维护文件未完整写入，请重新运行安装程序。" /SD IDOK
    SetErrorLevel 20
    Quit
  ${EndIf}
  WriteRegStr ${HIVE} "${REGKEY}" "DisplayName" "${PRODUCT}"
  WriteRegStr ${HIVE} "${REGKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr ${HIVE} "${REGKEY}" "Publisher" "${COMPANY}"
  WriteRegStr ${HIVE} "${REGKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr ${HIVE} "${REGKEY}" "DisplayIcon" "$INSTDIR\CodeSigner.App.exe"
  WriteRegStr ${HIVE} "${REGKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr ${HIVE} "${REGKEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegStr ${HIVE} "${REGKEY}" "URLInfoAbout" "https://www.anxinssl.com/code-signing-certificate/"
  WriteRegDWORD ${HIVE} "${REGKEY}" "NoModify" 1
  WriteRegDWORD ${HIVE} "${REGKEY}" "NoRepair" 1
  !ifndef AUTOMATED_TEST
    CreateDirectory "$SMPROGRAMS\${PRODUCT}"
    CreateShortcut "$SMPROGRAMS\${PRODUCT}\${PRODUCT}.lnk" "$INSTDIR\CodeSigner.App.exe"
    CreateShortcut "$SMPROGRAMS\${PRODUCT}\卸载.lnk" "$INSTDIR\Uninstall.exe"
    CreateShortcut "$DESKTOP\${PRODUCT}.lnk" "$INSTDIR\CodeSigner.App.exe"
  !endif
  Delete "$INSTDIR\CodeSigner.App.exe.previous"
  Delete "$INSTDIR\CodeSigner.Worker.exe.previous"
  SetErrorLevel 0
  install_done:
SectionEnd

Function un.onInit
  SetRegView 64
  !insertmacro FixedDirectory
  !insertmacro CheckDirectory
  !insertmacro CheckOwnedFiles
  !insertmacro AcquireMutex
  ReadRegStr $0 ${HIVE} "${REGKEY}" "InstallLocation"
  ${If} $0 != $INSTDIR
    SetErrorLevel 30
    Quit
  ${EndIf}
FunctionEnd

Section "Uninstall"
  ; Settings closes the application immediately after launching this uninstaller.
  Sleep 1500
  !macro UninstallCheck NAME
    ${If} ${FileExists} "$INSTDIR\${NAME}"
      System::Call 'kernel32::CreateFileW(w "$INSTDIR\${NAME}", i 0xC0000000, i 0, p 0, i 3, i 0, p 0) p .r1'
      ${If} $1 == -1
        MessageBox MB_ICONEXCLAMATION "请关闭工具后重新卸载。" /SD IDOK
        SetErrorLevel 10
        Quit
      ${EndIf}
      System::Call 'kernel32::CloseHandle(p r1)'
    ${EndIf}
  !macroend
  !insertmacro UninstallCheck "CodeSigner.App.exe"
  !insertmacro UninstallCheck "CodeSigner.Worker.exe"
  ClearErrors
  Delete "$INSTDIR\CodeSigner.App.exe"
  Delete "$INSTDIR\CodeSigner.Worker.exe"
  ${If} ${Errors}
    MessageBox MB_ICONEXCLAMATION "请关闭工具后重新卸载。" /SD IDOK
    SetErrorLevel 10
    Quit
  ${EndIf}
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\NOTICE"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\source-manifest.json"
  Delete "$INSTDIR\Maintenance\Setup.exe"
  RMDir "$INSTDIR\Maintenance"
  Delete "$INSTDIR\Uninstall.exe"
  !ifndef AUTOMATED_TEST
    Delete "$DESKTOP\${PRODUCT}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT}\${PRODUCT}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT}\卸载.lnk"
    RMDir "$SMPROGRAMS\${PRODUCT}"
  !endif
  DeleteRegKey ${HIVE} "${REGKEY}"
  RMDir "$INSTDIR"
  SetErrorLevel 0
SectionEnd
