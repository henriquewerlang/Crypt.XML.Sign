unit Crypt.XML.Sign.Test;

interface

uses Test.Insight.Framework;

type
  [TestFixture]
  TCertificateTest = class

  end;

  [TestFixture]
  TSignerTest = class
  public
    [Test]
    procedure Teste;
  end;

implementation

uses System.IOUtils, Crypt.XML.Sign;

{ TSignerTest }

procedure TSignerTest.Teste;
begin
  var Certificate := TCertificate.Create;
  var Signer := TSigner.Create;

  Certificate.Load('..\..\Certificate\Contoso.pfx', '123');

//  Signer.Sign(Certificate, '/nfeProc/NFe/Signature', TFile.ReadAllText('C:\Componentes\Windows-classic-samples\Samples\Win7Samples\security\cryptoapi\cryptxml\XML.xml'));
end;

end.
