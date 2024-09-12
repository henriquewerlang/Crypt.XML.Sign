program CryptXMLSignTest;

{$STRONGLINKTYPES ON}

uses
  Test.Insight.Framework,
  Crypt.XML.Sign.Test in 'Test\Crypt.XML.Sign.Test.pas',
  Crypt.XML.Sign in 'Crypt.XML.Sign.pas';

begin
  ReportMemoryLeaksOnShutdown := True;

  TTestInsightFramework.ExecuteTests;
end.

