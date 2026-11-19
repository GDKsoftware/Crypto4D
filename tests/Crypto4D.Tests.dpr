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
  Crypto4D.BigInteger in '..\src\Crypto4D.BigInteger.pas',
  Crypto4D.TestSupport in 'Crypto4D.TestSupport.pas',
  Crypto4D.BigInteger.Tests in 'Crypto4D.BigInteger.Tests.pas';

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
