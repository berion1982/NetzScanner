; NetzScanner - Windows-Installer (NSIS), I-085
;
; Wird NICHT von Hand gestartet, sondern von scripts/build-installer.sh mit
; diesen Vorgaben (-D):
;   VERSION  Versionsnummer (z. B. 0.53.0)
;   ARCH     amd64 oder arm64 (nur fuer den Dateinamen/Anzeige)
;   EXE      Pfad zur gebauten netzscanner-*.exe
;   LICENSE  Pfad zur AGPL-Lizenzdatei
;   THIRD    Pfad zu THIRD_PARTY_LICENSES.txt
;   ICO      Pfad zur .ico-Datei
;   OUTFILE  Ausgabedatei (Setup-Programm)
;
; Eigenschaften:
;  - Installation fuer ALLE Benutzer des Rechners (I-087): Ordner "C:\Program Files\NetzScanner",
;    Eintraege unter HKLM, Startmenue/Desktop fuer alle. Dafuer braucht das Setup
;    Administratorrechte (Windows fragt per UAC).
;  - Startmenue-Eintrag, optional Desktop-Verknuepfung.
;  - Eintrag unter "Apps & Features" mit Deinstallation.
;  - Die Deinstallation laesst die Eingaben der Benutzer (je Benutzer eingaben.json) unberuehrt.

Unicode true
!include "MUI2.nsh"

!define APPNAME "NetzScanner"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APPNAME}"
InstallDirRegKey HKLM "Software\${APPNAME}" "InstallDir"   ; bei Update denselben Ordner vorschlagen
RequestExecutionLevel admin                                 ; fuer alle Benutzer: UAC-Abfrage
SetCompressor /SOLID lzma

; Dateieigenschaften des Setup-Programms
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "FileDescription" "${APPNAME} Setup (${ARCH})"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "AGPL-3.0-or-later"

!define MUI_ICON "${ICO}"
!define MUI_UNICON "${ICO}"
!define MUI_ABORTWARNING

; Seitenfolge: Willkommen, Lizenz, Komponenten, Ordner, Installation, Fertig (mit "Starten")
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${LICENSE}"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
; Start ueber den Explorer, damit NetzScanner mit den normalen Rechten des Benutzers laeuft
; und NICHT mit den Administratorrechten des Setups.
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchAsUser
!define MUI_FINISHPAGE_RUN_TEXT "NetzScanner jetzt starten"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "German"

; Beim Start: 64-Bit-Registry und Eintraege/Verknuepfungen fuer alle Benutzer
Function .onInit
  SetRegView 64
  SetShellVarContext all
  ; Alte Einzelbenutzer-Installation (Setup 0.54/0.55) erkennen: sonst gaebe es zwei Eintraege
  ReadRegStr $0 HKCU "Software\${APPNAME}" "InstallDir"
  StrCmp $0 "" keineAlteInstallation
  MessageBox MB_ICONINFORMATION|MB_OK "Es ist noch eine frühere Installation nur für Ihren Benutzer vorhanden ($0).$\nBitte nach dieser Installation unter „Apps & Features“ den älteren Eintrag „${APPNAME}“ deinstallieren."
  keineAlteInstallation:
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function LaunchAsUser
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\netzscanner.exe"'
FunctionEnd

; --- Programm (Pflicht) ------------------------------------------------------
Section "NetzScanner (erforderlich)" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"
  ; Laeuft NetzScanner noch, ist die Datei gesperrt: NSIS fragt dann "Wiederholen/Abbrechen".
  File "/oname=netzscanner.exe" "${EXE}"
  File "/oname=LICENSE.txt" "${LICENSE}"
  File "/oname=THIRD_PARTY_LICENSES.txt" "${THIRD}"
  File "/oname=netzscanner.ico" "${ICO}"

  ; Startmenue
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\netzscanner.exe" "" "$INSTDIR\netzscanner.ico"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME} deinstallieren.lnk" "$INSTDIR\uninstall.exe"

  ; Deinstallationsprogramm und Eintrag unter "Apps & Features"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "${APPNAME}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\netzscanner.ico"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
SectionEnd

; --- Optional: Desktop-Verknuepfung ------------------------------------------
Section "Desktop-Verknüpfung" SecDesktop
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\netzscanner.exe" "" "$INSTDIR\netzscanner.ico"
SectionEnd

LangString DESC_Main ${LANG_GERMAN} "Das Programm selbst, Lizenztexte und Startmenü-Eintrag."
LangString DESC_Desktop ${LANG_GERMAN} "Legt zusätzlich eine Verknüpfung auf dem Desktop an."
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} $(DESC_Main)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} $(DESC_Desktop)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; --- Deinstallation ----------------------------------------------------------
; Entfernt nur, was der Installer angelegt hat. Die gespeicherten Eingaben
; (Namen, Standorte ...) liegen unter %APPDATA%\netzscanner und bleiben erhalten.
Section "Uninstall"
  Delete "$INSTDIR\netzscanner.exe"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\THIRD_PARTY_LICENSES.txt"
  Delete "$INSTDIR\netzscanner.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"                      ; nur wenn leer

  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME} deinstallieren.lnk"
  RMDir "$SMPROGRAMS\${APPNAME}"
  Delete "$DESKTOP\${APPNAME}.lnk"

  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "Software\${APPNAME}"
SectionEnd
