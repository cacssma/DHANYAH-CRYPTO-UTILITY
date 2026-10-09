; Inno Setup Script for Dhanyah Crypto Utility
; Unified FIPS 140-2/3 Level 3 Crypto Token Utility for India
; Author: CA Akash J. Bhayani (mail@ca-akash.in | https://ca-akash.in)

#define MyAppName "Dhanyah Crypto Utility"
#define MyAppVersion "1.0.1"
#define MyAppPublisher "CA Akash J. Bhayani"
#define MyAppURL "https://ca-akash.in"
#define MyAppRepoURL "https://github.com/cacssma/DHANYAH-CRYPTO-UTILITY"
#define MyAppExeName "DhanyahCryptoUtility.exe"

[Setup]
; Unique GUID for clean upgrade/uninstall tracking
AppId={{8B19C9D7-2483-484B-9E39-C46A258C8921}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppRepoURL}
AppUpdatesURL={#MyAppRepoURL}/releases
DefaultDirName={autopf}\Dhanyah Crypto Utility
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
LicenseFile=LICENSE
OutputDir=dist_installer
OutputBaseFilename=DhanyahCryptoUtility_Setup_v1.0.1
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=app_icon.ico
ArchitecturesInstallIn64BitMode=x64compatible
; Administrator privileges required for Windows Smart Card MiniDriver & CSP integration
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
RestartApplications=no
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\DhanyahCryptoUtility\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\DhanyahCryptoUtility\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
