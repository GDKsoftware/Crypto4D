program Crypto4D.VectorGenerator;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  System.IOUtils,
  Crypto4D.Errors in '..\..\src\Crypto4D.Errors.pas',
  Crypto4D.Bytes in '..\..\src\Crypto4D.Bytes.pas',
  Crypto4D.BigInteger in '..\..\src\Crypto4D.BigInteger.pas',
  Crypto4D.PrimeField in '..\..\src\Crypto4D.PrimeField.pas',
  Crypto4D.Hash in '..\..\src\Crypto4D.Hash.pas',
  Crypto4D.Der in '..\..\src\Crypto4D.Der.pas',
  Crypto4D.P256 in '..\..\src\Crypto4D.P256.pas',
  Crypto4D.Ecdsa in '..\..\src\Crypto4D.Ecdsa.pas',
  Crypto4D.Rsa in '..\..\src\Crypto4D.Rsa.pas',
  Crypto4D.Edwards25519 in '..\..\src\Crypto4D.Edwards25519.pas',
  Crypto4D.Ed25519 in '..\..\src\Crypto4D.Ed25519.pas',
  Crypto4D.X509 in '..\..\src\Crypto4D.X509.pas',
  Crypto4D.VectorGenerator.OpenSsl in 'Crypto4D.VectorGenerator.OpenSsl.pas',
  Crypto4D.VectorGenerator.CrossCheck in 'Crypto4D.VectorGenerator.CrossCheck.pas';

const
  DefaultSeed  = 20261119;
  UsageText    = 'Usage: Crypto4D.VectorGenerator <path to openssl.exe> <output file> [seed]';
  FolderPrefix = 'crypto4d-vectors-';

begin
  try
    const HasArguments = (ParamCount >= 2);
    if not HasArguments then
    begin
      System.Writeln(UsageText);
      System.ExitCode := 1;
      Exit;
    end;

    const Seed       = StrToIntDef(ParamStr(3), DefaultSeed);
    const FolderName = FolderPrefix + TGUID.NewGuid.ToString;
    const WorkFolder = TPath.Combine(TPath.GetTempPath, FolderName);
    TDirectory.CreateDirectory(WorkFolder);
    try
      const Tool = TOpenSslTool.Create(ParamStr(1), WorkFolder);
      try
        const Generator = TCrossCheckGenerator.Create(Tool, Seed);
        try
          Generator.Generate(ParamStr(2));
        finally
          Generator.Free;
        end;
      finally
        Tool.Free;
      end;
    finally
      TDirectory.Delete(WorkFolder, True);
    end;
  except
    on Error: Exception do
    begin
      System.Writeln(Format('%s: %s', [Error.ClassName, Error.Message]));
      System.ExitCode := 2;
    end;
  end;
end.
