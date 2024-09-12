unit Crypt.XML.Sign.Test;

interface

uses Test.Insight.Framework, Crypt.XML.Sign, Xml.XMLDoc, Xml.XMLIntf;

type
  [TestFixture]
  TCertificateTest = class
  public
    [Test]
    procedure WhenLoadTheCertificateMustLoadTheContext;
    [Test]
    procedure WhenLoadTheCertificateMustLoadThePrivateKeyHandle;
  end;

  [TestFixture]
  TCanonicalizationMethodTest = class
  public
    [Test]
    procedure WhenCreateTheCanonicalizationMethodC14MustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheCanonicalizationMethodC14WithCommentsMustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheCanonicalizationMethodC14ExclusiveMustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheCanonicalizationMethodC14ExclusiveWithCommentsMustLoadTheAlgorithmWithTheValueExpected;
  end;

  [TestFixture]
  TDigestMethodTest = class
  public
    [Test]
    procedure WhenCreateTheDigestMethodSHA1MustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheDigestMethodSHA256MustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheDigestMethodSHA384MustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheDigestMethodSHA512MustLoadTheAlgorithmWithTheValueExpected;
  end;

  [TestFixture]
  TTransformTest = class
  public
    [Test]
    procedure WhenCreateTheTransformBase64MustLoadTheAlgorithmWithTheValueExpected;
    [Test]
    procedure WhenCreateTheTransformEnvelopedMustLoadTheAlgorithmWithTheValueExpected;
  end;

  [TestFixture]
  TSignatureMethodTest = class
  public
    [Test]
    procedure WhenCreateTheSignatureMethodRSA_SHA1MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodDSA_SHA1MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodRSA_SHA256MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodRSA_SHA384MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodRSA_SHA512MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodECDSA_SHA1MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodECDSA_SHA256MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodECDSA_SHA384MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodECDSA_SHA512MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodHMAC_SHA1MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodHMAC_SHA256MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodHMAC_SHA384MustLoadTheAlgorithmTheValueExpected;
    [Test]
    procedure WhenCreateTheSignatureMethodHMAC_SHA512MustLoadTheAlgorithmTheValueExpected;
  end;

  [TestFixture]
  TSignerTest = class
  private
    FCertificate: TCertificate;
    FSigner: TSigner;

    function FindNode(const Node: IXMLNode; const NodeName: String): IXMLNode;
    function SignXML: IXMLNode;
  public
    [Setup]
    procedure Setup;
    [TearDown]
    procedure TearDown;
    [Test]
    procedure WhenSignAXMLMustExecuteWithoutErrors;
    [Test]
    procedure WhenFillTheCanonicalizationMethodMustSignTheXMLWithTheMethodLoaded;
    [Test]
    procedure WhenFillTheDigestMethodMustSignTheXMLWithTheMethodLoaded;
    [Test]
    procedure WhenFillTheSignatureMethodMustSignTheXMLWithTheMethodLoaded;
    [Test]
    procedure WhenAddATransformAlgorithmMustLoadThisInfoInTheXMLSigned;
    [Test]
    procedure WhenSignAXMLMustLoadTheSignatureInfoWithTheValuesOfTheSignature;
  end;

implementation

{ TCertificateTest }

procedure TCertificateTest.WhenLoadTheCertificateMustLoadTheContext;
begin
  var Certificate := TCertificate.Create;

  Certificate.Load('..\..\Certificate\Contoso.pfx', '123');

  Assert.IsNotNil(Certificate.Context);

  Certificate.Free;
end;

procedure TCertificateTest.WhenLoadTheCertificateMustLoadThePrivateKeyHandle;
begin
  var Certificate := TCertificate.Create;

  Certificate.Load('..\..\Certificate\Contoso.pfx', '123');

  Assert.GreaterThan(0, Certificate.PrivateKey);

  Certificate.Free;
end;

{ TSignerTest }

function TSignerTest.FindNode(const Node: IXMLNode; const NodeName: String): IXMLNode;
begin
  var ChildNode := Node.ChildNodes.First;
  Result := nil;

  while Assigned(ChildNode) and not Assigned(Result) do
  begin
    if ChildNode.NodeName = NodeName then
      Exit(ChildNode)
    else
      Result := FindNode(ChildNode, NodeName);

    ChildNode := ChildNode.NextSibling;
  end;
end;

procedure TSignerTest.Setup;
begin
  FCertificate := TCertificate.Create;
  FSigner := TSigner.Create;

  FCertificate.Load('..\..\Certificate\Contoso.pfx', '123');
end;

function TSignerTest.SignXML: IXMLNode;
begin
  var XML: IXMLDocument := TXMLDocument.Create(nil);

  XML.LoadFromXML(FSigner.SignXML(FCertificate, '/XML', '#SignXML', '<XML><Value Id="SignXML">ABC</Value></XML>'));

  Result := XML.ChildNodes.Last;
end;

procedure TSignerTest.TearDown;
begin
  FSigner.Free;

  FCertificate.Free;
end;

procedure TSignerTest.WhenAddATransformAlgorithmMustLoadThisInfoInTheXMLSigned;
begin
  FSigner.AddTransform(TCanonicalizationC14C.Create);
  FSigner.AddTransform(TTransformEveloped.Create);

  var Transform := FindNode(SignXML, 'Transform');

  Assert.AreEqual(FSigner.Transforms[0].wszAlgorithm, String(Transform.Attributes['Algorithm']));

  Transform := Transform.NextSibling;

  Assert.AreEqual(FSigner.Transforms[1].wszAlgorithm, String(Transform.Attributes['Algorithm']));
end;

procedure TSignerTest.WhenFillTheCanonicalizationMethodMustSignTheXMLWithTheMethodLoaded;
begin
  FSigner.CanonicalizationMethod := TCanonicalizationExclusiveC14CWithComments.Create;
  var SignatureNode := SignXML;

  Assert.AreEqual(FSigner.CanonicalizationMethod.Algorithm.wszAlgorithm, String(FindNode(SignatureNode, 'CanonicalizationMethod').Attributes['Algorithm']));
end;

procedure TSignerTest.WhenFillTheDigestMethodMustSignTheXMLWithTheMethodLoaded;
begin
  FSigner.DigestMethod := TDigestMethodSHA384.Create;
  var SignatureNode := SignXML;

  Assert.AreEqual(FSigner.DigestMethod.Algorithm.wszAlgorithm, String(FindNode(SignatureNode, 'DigestMethod').Attributes['Algorithm']));
end;

procedure TSignerTest.WhenFillTheSignatureMethodMustSignTheXMLWithTheMethodLoaded;
begin
  FSigner.SignatureMethod := TSignatureMethodRSA_SHA512.Create;
  var SignatureNode := SignXML;

  Assert.AreEqual(FSigner.SignatureMethod.Algorithm.wszAlgorithm, String(FindNode(SignatureNode, 'SignatureMethod').Attributes['Algorithm']));
end;

procedure TSignerTest.WhenSignAXMLMustExecuteWithoutErrors;
begin
  FSigner.SignXML(FCertificate, '/XML', '#SignXML', '<XML><Value Id="SignXML">ABC</Value></XML>');
end;

procedure TSignerTest.WhenSignAXMLMustLoadTheSignatureInfoWithTheValuesOfTheSignature;
begin
  var SignatureInfo := FSigner.Sign(FCertificate, '/XML', '#SignXML', '<XML><Value Id="SignXML">ABC</Value></XML>');

  Assert.IsNotEmpty(SignatureInfo.SignatureValue);

  Assert.AreEqual(
    'MIIDLjCCAhqgAwIBAgIQtQ/bA4dLHpxP4jq9bLqusjAJBgUrDgMCHQUAMB8xHTAbBgNVBAMTFENvbnRvc28gaW50ZXJtZWRpYXRlMB4XDTI0MDkwOTE3NDM0OVoXDTM5MTIzMTIzNTk1OV' +
    'owEjEQMA4GA1UEAxMHQ29udG9zbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOCAu+BG8UFri1U5mwb6eLYIKzqOoipFXgxHjg8HLeJgtrLZqkhzPS0Tv1j2/MTkG4ILtj5f' +
    'u4A/1BW+KXxWUt2raE5GUVl4hig2ThUIxbCMrcvImJeb3LDXcIXLCVhe7yWGFbzvROz6e1mMUxe4P9lwot7Ey1SeoI38v4jO1EYEjLb8hac8XHGEZ8eI+MK7+GZrdUfSSl11UaRwpnZzN/' +
    '8bxCoi+frOZ8j+bpGtSthLbf6Q7+oAFpo8gUQvDPcJfX3WUflmABiSTzDaSO6L3I1yxM2gaM1vUqt/cpMA53of/5HRmGvEaSSyaT4FUM/YLOUVxbxAzc01NCUcHelQm3kCAwEAAaN7MHkw' +
    'DAYDVR0TAQH/BAIwADAVBgNVHSUEDjAMBgorBgEEAYI3CgMMMFIGA1UdAQRLMEmAEAEgBgdchfZw2HS80kZ0ri6hIzAhMR8wHQYDVQQDExZDb250b3NvIFJvb3QgQXV0aG9yaXR5ghAzZm' +
    '8oEJLKnkdJApqE5DdIMAkGBSsOAwIdBQADggEBAJQkBFrgNEDnIR7LGTbM0DVKVJgG8cS4cf7TESJIBohn8BheEHKf0ghx4F11cl5sG2F2lq6/iF06z7uToi5V8E1a51l0vPctyBSgE2Vs' +
    'SbdzZj1OGeFaCwDhnnn7TuPa2sRT4JdYk20G4T/rhegY/QVTsgkBcJiDMKhyNbbdvTDOK05/tNZZds5Zu9kZnpn3qCfDw2eLqm1rBblmDbZxcfBNaZtl8X4aALNggd5rvcQWsex7vfDJ0C' +
    'yJZ595cphLVNCEQp9tjhUbW1Fv4MOnQ/ltPj7n7VjO+hPiEl3C4VGgHSXZ+bQKMPaktb0MiiLDG43ktgHfaXqFpB0Lbvu6Kiw=', SignatureInfo.X509Certificate);

  Assert.AreEqual('ORjDlIhaZHQECNlbguge8kQ6nOOlL5jJbMwmz+vDZqg=', SignatureInfo.DigestValue);
end;

{ TCanonicalizationMethodTest }

procedure TCanonicalizationMethodTest.WhenCreateTheCanonicalizationMethodC14ExclusiveMustLoadTheAlgorithmWithTheValueExpected;
begin
  var Canonicalization := TCanonicalizationExclusiveC14C.Create;

  Assert.AreEqual('http://www.w3.org/2001/10/xml-exc-c14n#', Canonicalization.Algorithm.wszAlgorithm);

  Canonicalization.Free;
end;

procedure TCanonicalizationMethodTest.WhenCreateTheCanonicalizationMethodC14ExclusiveWithCommentsMustLoadTheAlgorithmWithTheValueExpected;
begin
  var Canonicalization := TCanonicalizationExclusiveC14CWithComments.Create;

  Assert.AreEqual('http://www.w3.org/2001/10/xml-exc-c14n#WithComments', Canonicalization.Algorithm.wszAlgorithm);

  Canonicalization.Free;
end;

procedure TCanonicalizationMethodTest.WhenCreateTheCanonicalizationMethodC14MustLoadTheAlgorithmWithTheValueExpected;
begin
  var Canonicalization := TCanonicalizationC14C.Create;

  Assert.AreEqual('http://www.w3.org/TR/2001/REC-xml-c14n-20010315', Canonicalization.Algorithm.wszAlgorithm);

  Canonicalization.Free;
end;

procedure TCanonicalizationMethodTest.WhenCreateTheCanonicalizationMethodC14WithCommentsMustLoadTheAlgorithmWithTheValueExpected;
begin
  var Canonicalization := TCanonicalizationC14CWithComments.Create;

  Assert.AreEqual('http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments', Canonicalization.Algorithm.wszAlgorithm);

  Canonicalization.Free;
end;

{ TDigestMethodTest }

procedure TDigestMethodTest.WhenCreateTheDigestMethodSHA1MustLoadTheAlgorithmWithTheValueExpected;
begin
  var DigestMethod := TDigestMethodSHA1.Create;

  Assert.AreEqual('http://www.w3.org/2000/09/xmldsig#sha1', DigestMethod.Algorithm.wszAlgorithm);

  DigestMethod.Free;
end;

procedure TDigestMethodTest.WhenCreateTheDigestMethodSHA256MustLoadTheAlgorithmWithTheValueExpected;
begin
  var DigestMethod := TDigestMethodSHA256.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmlenc#sha256', DigestMethod.Algorithm.wszAlgorithm);

  DigestMethod.Free;
end;

procedure TDigestMethodTest.WhenCreateTheDigestMethodSHA384MustLoadTheAlgorithmWithTheValueExpected;
begin
  var DigestMethod := TDigestMethodSHA384.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#sha384', DigestMethod.Algorithm.wszAlgorithm);

  DigestMethod.Free;
end;

procedure TDigestMethodTest.WhenCreateTheDigestMethodSHA512MustLoadTheAlgorithmWithTheValueExpected;
begin
  var DigestMethod := TDigestMethodSHA512.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmlenc#sha512', DigestMethod.Algorithm.wszAlgorithm);

  DigestMethod.Free;
end;

{ TSignatureMethodTest }

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodDSA_SHA1MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodDSA_SHA1.Create;

  Assert.AreEqual('http://www.w3.org/2000/09/xmldsig#dsa-sha1', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodECDSA_SHA1MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodECDSA_SHA1.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodECDSA_SHA256MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodECDSA_SHA256.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodECDSA_SHA384MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodECDSA_SHA384.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodECDSA_SHA512MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodECDSA_SHA512.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodHMAC_SHA1MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodHMAC_SHA1.Create;

  Assert.AreEqual('http://www.w3.org/2000/09/xmldsig#hmac-sha1', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodHMAC_SHA256MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodHMAC_SHA256.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#hmac-sha256', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodHMAC_SHA384MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodHMAC_SHA384.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#hmac-sha384', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodHMAC_SHA512MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodHMAC_SHA512.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#hmac-sha512', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodRSA_SHA1MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodRSA_SHA1.Create;

  Assert.AreEqual('http://www.w3.org/2000/09/xmldsig#rsa-sha1', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodRSA_SHA256MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodRSA_SHA256.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodRSA_SHA384MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodRSA_SHA384.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#rsa-sha384', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

procedure TSignatureMethodTest.WhenCreateTheSignatureMethodRSA_SHA512MustLoadTheAlgorithmTheValueExpected;
begin
  var SignatureMethod := TSignatureMethodRSA_SHA512.Create;

  Assert.AreEqual('http://www.w3.org/2001/04/xmldsig-more#rsa-sha512', SignatureMethod.Algorithm.wszAlgorithm);

  SignatureMethod.Free;
end;

{ TTransformTest }

procedure TTransformTest.WhenCreateTheTransformBase64MustLoadTheAlgorithmWithTheValueExpected;
begin
  var Transform := TTransformBase64.Create;

  Assert.AreEqual('http://www.w3.org/2000/09/xmldsig#base64', Transform.Algorithm.wszAlgorithm);

  Transform.Free;
end;

procedure TTransformTest.WhenCreateTheTransformEnvelopedMustLoadTheAlgorithmWithTheValueExpected;
begin
  var Transform := TTransformEveloped.Create;

  Assert.AreEqual('http://www.w3.org/2000/09/xmldsig#enveloped-signature', Transform.Algorithm.wszAlgorithm);

  Transform.Free;
end;

end.

