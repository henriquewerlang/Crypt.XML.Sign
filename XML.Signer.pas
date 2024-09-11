unit XML.Signer;

interface

uses System.SysUtils, Winapi.Windows, Windows.Foundation, Windows.Security.Cryptography;

type
  TCertificate = class
  private
    FCertificate: PCERT_CONTEXT;
    FCertificateStore: HCERTSTORE;
    FKeySpec: CERT_KEY_SPEC;
    FPrivateKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
  public
    destructor Destroy; override;

    procedure Load(const Certificate: TBytes; const Password: String); overload;
    procedure Load(const FileName, Password: String); overload;

    property Certificate: PCERT_CONTEXT read FCertificate;
    property KeySpec: CERT_KEY_SPEC read FKeySpec;
    property PrivateKey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE read FPrivateKey;
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
    function Sign(const Certificate: TCertificate; const SignaturePath, URI, XML: String): String;
  end;

implementation

uses System.IOUtils;

function CertGetCertificateChain(hChainEngine: HCERTCHAINENGINE; pCertContext: PCERT_CONTEXT; pTime: PFILETIME; hAdditionalStore: HCERTSTORE; pChainPara: PCERT_CHAIN_PARA; dwFlags: Cardinal; pvReserved: PPointer; out ppChainContext: PCERT_CHAIN_CONTEXT): BOOL; stdcall; external 'CRYPT32.dll' name 'CertGetCertificateChain';

function WriteXML(Callback: PPointer; Data: PByte; Size: Cardinal): HRESULT; stdcall;
begin
  PString(Callback^)^ := PString(Callback^)^ + TEncoding.UTF8.GetString(TBytes(Data), 0, Size);
end;


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

  FCertificate := CertFindCertificateInStore(FCertificateStore, X509_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, nil, nil);

  if not Assigned(FCertificate) then
    raise Exception.Create('A valid certificate doesn''t found!');

  var CallerFree: BOOL := FALSE;

  if CryptAcquireCertificatePrivateKey(FCertificate, CRYPT_ACQUIRE_CACHE_FLAG, nil, FPrivateKey, @KeySpec, @CallerFree) = FALSE then
    RaiseLastOSError;
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

function TSigner.Sign(const Certificate: TCertificate; const SignaturePath, URI, XML: String): String;

  function CreateAlgorithm(const NameSpace: String): CRYPT_XML_ALGORITHM;
  begin
    Result.cbSize := SizeOf(Result);
    Result.Encoded.cbData := 0;
    Result.Encoded.dwCharset := CRYPT_XML_CHARSET_AUTO;
    Result.Encoded.pbData := nil;
    Result.wszAlgorithm := PChar(NameSpace);
  end;

  procedure CheckReturn(const Value: HRESULT);
  begin
    if Value <> S_OK then
      RaiseLastOSError;
  end;

begin
  var CanonicalizationMethod := CreateAlgorithm(wszURI_CANONICALIZATION_EXSLUSIVE_C14N);
  var CertificateBlob: CERT_BLOB;
  var Chain := TCertificateChain.Create;
  var DigestMethod := CreateAlgorithm(wszURI_XMLNS_DIGSIG_SHA1);
  var EncodedXML: CRYPT_XML_BLOB;
  var KeyInfo: CRYPT_XML_KEYINFO_PARAM;
  var Path := PChar(SignaturePath);
  var Properties: CRYPT_XML_PROPERTY;
  var ReferenceValue: Pointer := nil;
  var SelfValue: Pointer := @Result;
  var SignatureMethod := CreateAlgorithm(wszURI_XMLNS_DIGSIG_RSA_SHA1);
  var ValueTrue: BOOL := TRUE;
  var XMLConverted := TEncoding.UTF8.GetBytes(XML);

  Properties.dwPropId := CRYPT_XML_PROPERTY_SIGNATURE_LOCATION;
  Properties.cbValue := SizeOf(LPCWSTR);
  Properties.pvValue := @Path;

  Chain.Load(Certificate);

  EncodedXML.cbData := Length(XMLConverted);
  EncodedXML.dwCharset := CRYPT_XML_CHARSET_UTF8;
  EncodedXML.pbData := @XMLConverted[0];

  FillChar(KeyInfo, SizeOf(KeyInfo), 0);

  KeyInfo.cCertificate := 1;
  KeyInfo.rgCertificate := @CertificateBlob;

  CertificateBlob.cbData := Certificate.Certificate.cbCertEncoded;
  CertificateBlob.pbData := Certificate.Certificate.pbCertEncoded;

  CheckReturn(CryptXmlOpenToEncode(nil, 0, nil, @Properties, 1, @EncodedXML, FSignature));

  CheckReturn(CryptXmlCreateReference(FSignature, 0, nil, PChar(URI), nil, @DigestMethod, 0, nil, ReferenceValue));

  CheckReturn(CryptXmlSign(FSignature, Certificate.PrivateKey, Certificate.KeySpec, 0, CRYPT_XML_KEYINFO_SPEC_PARAM, @KeyInfo, @SignatureMethod, @CanonicalizationMethod));

  Properties.dwPropId := CRYPT_XML_PROPERTY_DOC_DECLARATION;
  Properties.cbValue := SizeOf(ValueTrue);
  Properties.pvValue := @ValueTrue;

  CheckReturn(CryptXmlEncode(FSignature, CRYPT_XML_CHARSET_UTF8, @Properties, 1, SelfValue, WriteXML));
end;

end.

