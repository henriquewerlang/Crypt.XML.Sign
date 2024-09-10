unit XML.Signer;

interface

uses System.SysUtils, Winapi.Windows, Windows.Foundation, Windows.Security.Cryptography;

type
  TCertificate = class
  private
    FCertificate: PCERT_CONTEXT;
    FCertificateStore: HCERTSTORE;
  public
    destructor Destroy; override;

    procedure Load(const Certificate: TBytes; const Password: String); overload;
    procedure Load(const FileName, Password: String); overload;

    property Certificate: PCERT_CONTEXT read FCertificate;
  end;

  TCertificateChain = class
  private
    FChain: PCERT_CHAIN_CONTEXT;
  public
    destructor Destroy; override;

    procedure Load(const Certificate: TCertificate);

    property Chain: PCERT_CHAIN_CONTEXT read FChain write FChain;
  end;

  TSigner = class
  private
    FSignature: Pointer;
  public
    procedure Sign(const Certificate: TCertificate; const SignaturePath, XML: String);
  end;

implementation

uses System.IOUtils;

function CertGetCertificateChain(hChainEngine: HCERTCHAINENGINE; pCertContext: PCERT_CONTEXT; pTime: PFILETIME; hAdditionalStore: HCERTSTORE; pChainPara: PCERT_CHAIN_PARA; dwFlags: Cardinal; pvReserved: PPointer; out ppChainContext: PCERT_CHAIN_CONTEXT): BOOL; stdcall; external 'CRYPT32.dll' name 'CertGetCertificateChain';
//function CryptXmlOpenToEncode(pConfig: PCRYPT_XML_TRANSFORM_CHAIN_CONFIG; dwFlags: CRYPT_XML_FLAGS; wszId: PWSTR; rgProperty: PCRYPT_XML_PROPERTY; cProperty: Cardinal; pEncoded: PCRYPT_XML_BLOB; phSignature: Pointer): HRESULT; stdcall; external 'CRYPTXML.dll' name 'CryptXmlOpenToEncode';

{ TCertificate }

destructor TCertificate.Destroy;
begin
  if Assigned(FCertificate) then
    CertFreeCertificateContext(FCertificate);

  if Assigned(FCertificateStore) then
    CertCloseStore(FCertificateStore, 0);

  inherited;
end;

procedure TCertificate.Load(const FileName, Password: String);
begin
  Load(TFile.ReadAllBytes(FileName), Password);
end;

procedure TCertificate.Load(const Certificate: TBytes; const Password: String);
begin
  var Blob: CRYPT_INTEGER_BLOB;
  Blob.cbData := Length(Certificate);
  Blob.pbData := @Certificate[0];

  FCertificateStore := PFXImportCertStore(@Blob, PChar(Password), 0);

  if not Assigned(FCertificateStore) then
    raise Exception.Create('Can''t load the certificate file!');

  FCertificate := CertFindCertificateInStore(FCertificateStore, X509_ASN_ENCODING or PKCS_7_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, nil, nil);

  if not Assigned(FCertificate) then
    raise Exception.Create('A valid certificate doesn''t found!');
end;

{ TCertificateChain }

destructor TCertificateChain.Destroy;
begin
  if Assigned(FChain) then
    CertFreeCertificateChain(FChain);

  inherited;
end;

procedure TCertificateChain.Load(const Certificate: TCertificate);
begin
  var Params: CERT_CHAIN_PARA;

  FillChar(Params, SizeOf(Params), 0);

  if CertGetCertificateChain(0, Certificate.Certificate, nil, nil, @Params, 0, nil, FChain) = FALSE then
    RaiseLastOSError;
end;

{ TSigner }

procedure TSigner.Sign(const Certificate: TCertificate; const SignaturePath, XML: String);
begin
  var Chain := TCertificateChain.Create;
  var EncodedXML: CRYPT_XML_BLOB;
  var Properties: TArray<CRYPT_XML_PROPERTY>;
  var XMLConverted := TEncoding.UTF8.GetBytes(XML);

  SetLength(Properties, 1);

  Properties[0].dwPropId := CRYPT_XML_PROPERTY_SIGNATURE_LOCATION;
  Properties[0].cbValue := SizeOf(LPCWSTR);
  Properties[0].pvValue := PChar(SignaturePath);

  Chain.Load(Certificate);

  EncodedXML.cbData := Length(XMLConverted);
  EncodedXML.dwCharset := CRYPT_XML_CHARSET_UTF8;
  EncodedXML.pbData := @XMLConverted[0];

  if CryptXmlOpenToEncode(nil, 0, nil, @Properties[0], 1, @EncodedXML, FSignature) <> S_OK then
    RaiseLastOSError;
end;

end.

