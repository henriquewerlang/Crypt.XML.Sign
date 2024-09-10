program XMLSignerTest;

{$STRONGLINKTYPES ON}

uses
  Test.Insight.Framework,
  XML.Signer.Test in 'Test\XML.Signer.Test.pas',
  XML.Signer in 'XML.Signer.pas';

begin
  ReportMemoryLeaksOnShutdown := True;

  TTestInsightFramework.ExecuteTests;
end.

