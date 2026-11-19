program Crypto4D.Tests;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

{$R *.res}

uses
  System.SysUtils,
  DUnitX.TestFramework,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  Crypto4D.Errors in '..\src\Crypto4D.Errors.pas',
  Crypto4D.Bytes in '..\src\Crypto4D.Bytes.pas',
  Crypto4D.BigInteger in '..\src\Crypto4D.BigInteger.pas',
  Crypto4D.PrimeField in '..\src\Crypto4D.PrimeField.pas',
  Crypto4D.Hash in '..\src\Crypto4D.Hash.pas',
  Crypto4D.Der in '..\src\Crypto4D.Der.pas',
  Crypto4D.P256 in '..\src\Crypto4D.P256.pas',
  Crypto4D.Ecdsa in '..\src\Crypto4D.Ecdsa.pas',
  Crypto4D.Rsa in '..\src\Crypto4D.Rsa.pas',
  Crypto4D.Edwards25519 in '..\src\Crypto4D.Edwards25519.pas',
  Crypto4D.Ed25519 in '..\src\Crypto4D.Ed25519.pas',
  Crypto4D.X509 in '..\src\Crypto4D.X509.pas',
  Crypto4D.TestSupport in 'Crypto4D.TestSupport.pas',
  Crypto4D.BigInteger.Tests in 'Crypto4D.BigInteger.Tests.pas',
  Crypto4D.Der.Tests in 'Crypto4D.Der.Tests.pas',
  Crypto4D.Ecdsa.Tests in 'Crypto4D.Ecdsa.Tests.pas',
  Crypto4D.Rsa.Tests in 'Crypto4D.Rsa.Tests.pas',
  Crypto4D.Ed25519.Tests in 'Crypto4D.Ed25519.Tests.pas',
  Crypto4D.X509.Tests in 'Crypto4D.X509.Tests.pas',
  Crypto4D.Wycheproof.Tests in 'Crypto4D.Wycheproof.Tests.pas',
  Crypto4D.OpenSsl.Tests in 'Crypto4D.OpenSsl.Tests.pas',
  Crypto4D.Benchmark.Tests in 'Crypto4D.Benchmark.Tests.pas';

begin
  try
    TDUnitX.CheckCommandLine;

    const Runner = TDUnitX.CreateRunner;
    Runner.UseRTTI          := True;
    Runner.FailsOnNoAsserts := True;

    const QuietConsole                 = (TDUnitX.Options.ConsoleMode = TDunitXConsoleMode.Quiet);
    const ConsoleLogger: ITestLogger   = TDUnitXConsoleLogger.Create(QuietConsole);
    const XmlLogger: ITestLogger       = TDUnitXXMLNUnitFileLogger.Create(TDUnitX.Options.XMLOutputFile);
    Runner.AddLogger(ConsoleLogger);
    Runner.AddLogger(XmlLogger);

    const Results = Runner.Execute;
    System.ExitCode := Ord(not Results.AllPassed);
  except
    on Error: Exception do
    begin
      System.Writeln(Format('%s: %s', [Error.ClassName, Error.Message]));
      System.ExitCode := 2;
    end;
  end;
end.
