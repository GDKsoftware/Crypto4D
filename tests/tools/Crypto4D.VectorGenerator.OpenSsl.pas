unit Crypto4D.VectorGenerator.OpenSsl;

interface

uses
  System.SysUtils,
  System.SyncObjs;

type
  EOpenSslToolError = class(Exception);

  {$SCOPEDENUMS ON}
  TOpenSslVerdict = (Verified, VerificationFailure, SignatureRejected, KeyRejected);
  {$SCOPEDENUMS OFF}

  TOpenSslVerdictHelper = record helper for TOpenSslVerdict
    function Text: string;
  end;

  TOpenSslResult = record
    ExitCode: Cardinal;
    Output: string;
    Errors: string;
  end;

  TOpenSslTool = class
  private
    FExecutable: string;
    FWorkFolder: string;
    FLaunchLock: TCriticalSection;
    FRunCount: Integer;

    procedure GuardExecutable;
    function BuildCommandLine(const Arguments: TArray<string>): string;
    function Launch(const CommandLine, OutputFile, ErrorFile: string): THandle;
    function OpenInheritableFile(const FileName: string): THandle;
    function WaitForExit(const Process: THandle): Cardinal;
    function ReadText(const FileName: string): string;

  public
    constructor Create(const Executable, WorkFolder: string);
    destructor Destroy; override;

    function Run(const Arguments: TArray<string>): TOpenSslResult;
    function RunChecked(const Arguments: TArray<string>): TOpenSslResult;
    function Version: string;
    procedure GenerateKey(const KeyFile, Algorithm, Option: string);
    function PublicKeyDer(const KeyFile: string): TBytes;
    procedure Sign(const KeyFile, MessageFile, SignatureFile: string; const RawInput: Boolean);
    function Verdict(const PublicKeyFile, MessageFile, SignatureFile: string; const RawInput: Boolean): TOpenSslVerdict;

    property WorkFolder: string read FWorkFolder;
  end;

implementation

uses
  Winapi.Windows,
  System.IOUtils;

resourcestring
  ExecutableNotFound = 'The OpenSSL executable "%s" was not found';
  CannotCreateFile   = 'Cannot create "%s": %s';
  CannotStartProcess = 'Cannot start "%s": %s';
  CommandFailed      = 'openssl %s failed with exit code %d: %s';
  UnexpectedOutcome  = 'Unexpected OpenSSL outcome (exit code %d): %s %s';
  UnknownVerdict     = 'Unknown verdict %d';

const
  DerFormat = 'DER';

function TOpenSslVerdictHelper.Text: string;
begin
  case Self of
    TOpenSslVerdict.Verified            : Result := 'verified';
    TOpenSslVerdict.VerificationFailure : Result := 'verification failure';
    TOpenSslVerdict.SignatureRejected   : Result := 'signature rejected';
    TOpenSslVerdict.KeyRejected         : Result := 'key rejected';
  else
    raise EOpenSslToolError.CreateFmt(UnknownVerdict, [Ord(Self)]);
  end;
end;

constructor TOpenSslTool.Create(const Executable, WorkFolder: string);
begin
  inherited Create;
  FExecutable := Executable;
  FWorkFolder := WorkFolder;
  FLaunchLock := TCriticalSection.Create;

  GuardExecutable;
end;

destructor TOpenSslTool.Destroy;
begin
  FLaunchLock.Free;
  inherited Destroy;
end;

procedure TOpenSslTool.GuardExecutable;
begin
  if not TFile.Exists(FExecutable) then
    raise EOpenSslToolError.CreateFmt(ExecutableNotFound, [FExecutable]);
end;

function TOpenSslTool.Version: string;
begin
  const Outcome = RunChecked(['version']);
  Result := Outcome.Output.Trim;
end;

procedure TOpenSslTool.GenerateKey(const KeyFile, Algorithm, Option: string);
begin
  var Arguments: TArray<string> := ['genpkey', '-algorithm', Algorithm, '-out', KeyFile];
  if not Option.IsEmpty then
    Arguments := Arguments + ['-pkeyopt', Option];

  RunChecked(Arguments);
end;

function TOpenSslTool.PublicKeyDer(const KeyFile: string): TBytes;
begin
  const PublicKeyFile = TPath.ChangeExtension(KeyFile, '.public.der');
  RunChecked(['pkey', '-in', KeyFile, '-pubout', '-outform', DerFormat, '-out', PublicKeyFile]);

  Result := TFile.ReadAllBytes(PublicKeyFile);
end;

procedure TOpenSslTool.Sign(const KeyFile, MessageFile, SignatureFile: string; const RawInput: Boolean);
begin
  if RawInput then
    RunChecked(['pkeyutl', '-sign', '-inkey', KeyFile, '-rawin', '-in', MessageFile, '-out', SignatureFile])
  else
    RunChecked(['dgst', '-sha256', '-sign', KeyFile, '-out', SignatureFile, MessageFile]);
end;

function TOpenSslTool.Verdict(const PublicKeyFile, MessageFile, SignatureFile: string; const RawInput: Boolean): TOpenSslVerdict;
begin
  var Outcome: TOpenSslResult;
  if RawInput then
    Outcome := Run(['pkeyutl', '-verify', '-pubin', '-inkey', PublicKeyFile, '-keyform', DerFormat,
                    '-rawin', '-in', MessageFile, '-sigfile', SignatureFile])
  else
    Outcome := Run(['dgst', '-sha256', '-verify', PublicKeyFile, '-keyform', DerFormat,
                    '-signature', SignatureFile, MessageFile]);

  const HasVerified         = (Outcome.ExitCode = 0);
  const ReportsFailure      = Outcome.Output.ToLower.Contains('verification failure');
  const RejectsSignature    = Outcome.Errors.Contains('Error verifying data');
  const RejectsKey          = Outcome.Errors.Contains('Could not find') and Outcome.Errors.Contains('key');

  if HasVerified then
    Result := TOpenSslVerdict.Verified
  else if ReportsFailure then
    Result := TOpenSslVerdict.VerificationFailure
  else if RejectsSignature then
    Result := TOpenSslVerdict.SignatureRejected
  else if RejectsKey then
    Result := TOpenSslVerdict.KeyRejected
  else
    raise EOpenSslToolError.CreateFmt(UnexpectedOutcome, [Outcome.ExitCode, Outcome.Output, Outcome.Errors]);
end;

function TOpenSslTool.RunChecked(const Arguments: TArray<string>): TOpenSslResult;
begin
  Result := Run(Arguments);

  const HasFailed = (Result.ExitCode <> 0);
  if HasFailed then
    raise EOpenSslToolError.CreateFmt(CommandFailed, [string.Join(' ', Arguments), Result.ExitCode, Result.Errors]);
end;

function TOpenSslTool.Run(const Arguments: TArray<string>): TOpenSslResult;
begin
  const RunNumber   = TInterlocked.Increment(FRunCount);
  const OutputFile  = TPath.Combine(FWorkFolder, Format('stdout-%d.txt', [RunNumber]));
  const ErrorFile   = TPath.Combine(FWorkFolder, Format('stderr-%d.txt', [RunNumber]));
  const CommandLine = BuildCommandLine(Arguments);

  const Process = Launch(CommandLine, OutputFile, ErrorFile);
  try
    Result.ExitCode := WaitForExit(Process);
  finally
    CloseHandle(Process);
  end;

  Result.Output := ReadText(OutputFile);
  Result.Errors := ReadText(ErrorFile);
  TFile.Delete(OutputFile);
  TFile.Delete(ErrorFile);
end;

function TOpenSslTool.BuildCommandLine(const Arguments: TArray<string>): string;
begin
  Result := Format('"%s"', [FExecutable]);
  for var Argument in Arguments do
  begin
    Result := Format('%s "%s"', [Result, Argument]);
  end;
end;

function TOpenSslTool.Launch(const CommandLine, OutputFile, ErrorFile: string): THandle;
begin
  var MutableCommandLine := CommandLine;
  UniqueString(MutableCommandLine);
  var ProcessInfo := Default(TProcessInformation);
  var StartupInfo := Default(TStartupInfo);
  StartupInfo.cb      := SizeOf(StartupInfo);
  StartupInfo.dwFlags := STARTF_USESTDHANDLES;

  FLaunchLock.Enter;
  try
    StartupInfo.hStdOutput := OpenInheritableFile(OutputFile);
    StartupInfo.hStdError  := OpenInheritableFile(ErrorFile);
    try
      const Started = CreateProcess(nil, PChar(MutableCommandLine), nil, nil, True, CREATE_NO_WINDOW, nil, nil,
                                    StartupInfo, ProcessInfo);
      if not Started then
        raise EOpenSslToolError.CreateFmt(CannotStartProcess, [FExecutable, SysErrorMessage(GetLastError)]);
    finally
      CloseHandle(StartupInfo.hStdOutput);
      CloseHandle(StartupInfo.hStdError);
    end;
  finally
    FLaunchLock.Leave;
  end;

  CloseHandle(ProcessInfo.hThread);
  Result := ProcessInfo.hProcess;
end;

function TOpenSslTool.OpenInheritableFile(const FileName: string): THandle;
begin
  var Security := Default(TSecurityAttributes);
  Security.nLength        := SizeOf(Security);
  Security.bInheritHandle := True;

  Result := CreateFile(PChar(FileName), GENERIC_WRITE, FILE_SHARE_READ, @Security, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, 0);
  const HasFailed = (Result = INVALID_HANDLE_VALUE);
  if HasFailed then
    raise EOpenSslToolError.CreateFmt(CannotCreateFile, [FileName, SysErrorMessage(GetLastError)]);
end;

function TOpenSslTool.WaitForExit(const Process: THandle): Cardinal;
begin
  WaitForSingleObject(Process, INFINITE);
  GetExitCodeProcess(Process, Result);
end;

function TOpenSslTool.ReadText(const FileName: string): string;
begin
  const Content = TFile.ReadAllBytes(FileName);
  Result := TEncoding.ANSI.GetString(Content);
end;

end.
