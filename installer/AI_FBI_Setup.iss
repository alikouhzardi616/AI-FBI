#define AppName "AI FBI"
#define AppVersion "1.0.0"
#define AppPublisher "Ali Kouhzardi"
#define AppExeName "AI FBI.exe"

[Setup]
AppId={{E7A8B92B-B0B9-4B42-9E54-6DFD13FA1B0E}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\AI FBI
DefaultGroupName=AI FBI
UninstallDisplayIcon={app}\{#AppExeName}
LicenseFile=AI_FBI_License.txt
OutputDir=..\dist
OutputBaseFilename=AI_FBI_Installer
SetupIconFile=..\assets\ai_fbi.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Files]
Source: "..\dist\AI FBI.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\AI FBI"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\AI FBI"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch AI FBI"; Flags: postinstall nowait skipifsilent
