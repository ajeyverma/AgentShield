; ==============================================================================
; Subway Coders AI Agent — Inno Setup Script (Standalone Windows Installer)
; ==============================================================================

#define MyAppName "Subway Coders AI Agent"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Subway Coders & AgentShield AI"
#define MyAppURL "https://github.com/ajeyverma/AgentShield"
#define MyAppExeName "SubwayCodersAgent.exe"

[Setup]
AppId={{9C5E3D82-1B62-4C91-A9D4-8F747DE294F1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Subway Coders Agent
DisableProgramGroupPage=yes
OutputBaseFilename=SubwayCodersAgent-Setup-v{#MyAppVersion}
SetupIconFile=..\..\demos\agent\subway_coders.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=lowest
OutputDir=..\..\dist\installer

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Standalone compiled distribution files
Source: "..\..\dist\SubwayCodersAgent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Bundled pre-configured environment file (connected to Railway cloud)
Source: "..\..\dist\SubwayCodersAgent\.env"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
Source: "..\..\dist\SubwayCodersAgent\.env"; DestDir: "{app}"; DestName: ".env.default"; Flags: ignoreversion
Source: "..\..\demos\agent\subway_coders.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\subway_coders.ico"
Name: "{autoprograms}\Configure Subway Coders (.env)"; Filename: "notepad.exe"; Parameters: """{app}\.env"""
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; IconFilename: "{app}\subway_coders.ico"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\*.log"
Type: files; Name: "{app}\agentshield_dev.db"
