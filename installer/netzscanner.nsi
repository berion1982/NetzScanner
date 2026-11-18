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
;  - Installation nur fuer den aktuellen Benutzer, KEINE Administratorrechte noetig
;    (Ordner %LOCALAPPDATA%\Programs\NetzScanner, Eintraege unter HKCU).
;  - Startmenue-Eintrag, optional Desktop-Verknuepfung.
;  - Eintrag unter "Apps & Features" mit Deinstallation.
;  - Die Deinstallation laesst die Eingaben des Benutzers (eingaben.json) unberuehrt.

Unicode true
!include "MUI2.nsh"

!define APPNAME "NetzScanner"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

Name "${APPNAME} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${APPNAME}"
InstallDirRegKey HKCU "Software\${APPNAME}" "InstallDir"   ; bei Update denselben Ordner vorschlagen
RequestExecutionLevel user                                  ; kein UAC-Dialog
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
!define MUI_FINISHPAGE_RUN "$INSTDIR\netzscanner.exe"
!define MUI_FINISHPAGE_RUN_TEXT "NetzScanner jetzt starten"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "German"

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
  WriteRegStr HKCU "Software\${APPNAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\netzscanner.ico"
  WriteRegStr HKCU "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
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

  DeleteRegKey HKCU "${UNINSTKEY}"
  DeleteRegKey HKCU "Software\${APPNAME}"
SectionEnd
