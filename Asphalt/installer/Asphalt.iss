; Asphalt Installer (Inno Setup)

[Setup]
AppId={{B8B87D1D-7D4B-4C2B-9A46-3F6D3C5A0B9E}
AppName=Asphalt
AppVersion=1.0.0
AppPublisher=David Ren
DefaultDirName={pf}\Asphalt
DefaultGroupName=Asphalt
OutputDir=dist-installer
OutputBaseFilename=Asphalt-Setup
SetupIconFile=..\icon\icon.ico
UninstallDisplayIcon={app}\Asphalt.exe
Compression=lzma
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "..\dist\Asphalt.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Asphalt"; Filename: "{app}\Asphalt.exe"; IconFilename: "{app}\Asphalt.exe"
Name: "{commondesktop}\Asphalt"; Filename: "{app}\Asphalt.exe"; Tasks: desktopicon; IconFilename: "{app}\Asphalt.exe"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\Asphalt.exe"; Description: "Launch Asphalt"; Flags: nowait postinstall skipifsilent

[Code]
function IsNpcapInstalled(): Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\Npcap') or RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and (not IsNpcapInstalled()) then
  begin
    MsgBox('Npcap is required for live capture. Install it with WinPcap API-compatible mode from https://npcap.com/.', mbInformation, MB_OK);
  end;
end;
