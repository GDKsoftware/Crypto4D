unit Crypto4D.X509;

interface

uses
  System.SysUtils,
  Crypto4D.Der,
  Crypto4D.Ecdsa,
  Crypto4D.Rsa;

type
  TX509Oid = record
  public
    const
      EcPublicKey       = '1.2.840.10045.2.1';
      Prime256v1        = '1.2.840.10045.3.1.7';
      EcdsaWithSha256   = '1.2.840.10045.4.3.2';
      RsaEncryption     = '1.2.840.113549.1.1.1';
      Sha256WithRsa     = '1.2.840.113549.1.1.11';
      Ed25519           = '1.3.101.112';
  end;

  TX509AlgorithmIdentifier = record
  private
    FOid: string;
    FParameters: TBytes;

  public
    class function TryParse(const Element: TDerElement; out Algorithm: TX509AlgorithmIdentifier): Boolean; static;

    function HasNoParameters: Boolean;
    function HasNullOrNoParameters: Boolean;
    function IsSameAs(const Other: TX509AlgorithmIdentifier): Boolean;

    property Oid: string read FOid;
    property Parameters: TBytes read FParameters;
  end;

  TX509PublicKeyInfo = record
  private
    FAlgorithm: TX509AlgorithmIdentifier;
    FKeyBytes: TBytes;
    FEncoded: TBytes;

    class function TryParseElement(const Element: TDerElement; out PublicKey: TX509PublicKeyInfo): Boolean; static;

  public
    class function TryParse(const Der: TBytes; out PublicKey: TX509PublicKeyInfo): Boolean; static;

    function TryGetEcdsaP256Key(out Key: TEcdsaP256PublicKey): Boolean;
    function TryGetRsaKey(out Key: TRsaPublicKey): Boolean;
    function TryGetEd25519Key(out Key: TBytes): Boolean;

    property Algorithm: TX509AlgorithmIdentifier read FAlgorithm;
    property KeyBytes: TBytes read FKeyBytes;
    property Encoded: TBytes read FEncoded;
  end;

  TX509Extension = record
  private
    FOid: string;
    FCritical: Boolean;
    FValue: TBytes;

  public
    class function TryParse(const Element: TDerElement; out Extension: TX509Extension): Boolean; static;

    property Oid: string read FOid;
    property Critical: Boolean read FCritical;
    property Value: TBytes read FValue;
  end;

  TX509Certificate = record
  private
    const
      VersionTagNumber    = 0;
      IssuerIdTagNumber   = 1;
      SubjectIdTagNumber  = 2;
      ExtensionsTagNumber = 3;
      DefaultVersion      = 1;
      HighestVersion      = 3;
      PrimitiveContext    = $80;

    var
      FTbsCertificate: TBytes;
      FVersion: Integer;
      FSerialNumber: TBytes;
      FTbsSignatureAlgorithm: TX509AlgorithmIdentifier;
      FIssuer: TBytes;
      FValidity: TBytes;
      FSubject: TBytes;
      FPublicKey: TX509PublicKeyInfo;
      FExtensions: TArray<TX509Extension>;
      FSignatureAlgorithm: TX509AlgorithmIdentifier;
      FSignature: TBytes;

    function TryParseTbsCertificate(const Content: TBytes): Boolean;
    function TryReadVersion(var Reader: TDerReader): Boolean;
    function TryReadNames(var Reader: TDerReader): Boolean;
    function TryReadOptionalFields(var Reader: TDerReader): Boolean;
    function TrySkipUniqueId(var Reader: TDerReader; const TagNumber: Byte): Boolean;
    function TryReadExtensions(var Reader: TDerReader): Boolean;
    function TryParseExtensionList(const Content: TBytes): Boolean;
    function HasExtension(const Oid: string): Boolean;
    function VerifyEcdsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
    function VerifyRsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
    function VerifyEd25519(const IssuerKey: TX509PublicKeyInfo): Boolean;

  public
    class function TryParse(const Der: TBytes; out Certificate: TX509Certificate): Boolean; static;

    function TryFindExtension(const Oid: string; out Extension: TX509Extension): Boolean;
    function IsSignedBy(const IssuerKey: TX509PublicKeyInfo): Boolean;

    property TbsCertificate: TBytes read FTbsCertificate;
    property Version: Integer read FVersion;
    property SerialNumber: TBytes read FSerialNumber;
    property TbsSignatureAlgorithm: TX509AlgorithmIdentifier read FTbsSignatureAlgorithm;
    property Issuer: TBytes read FIssuer;
    property Validity: TBytes read FValidity;
    property Subject: TBytes read FSubject;
    property PublicKey: TX509PublicKeyInfo read FPublicKey;
    property Extensions: TArray<TX509Extension> read FExtensions;
    property SignatureAlgorithm: TX509AlgorithmIdentifier read FSignatureAlgorithm;
    property Signature: TBytes read FSignature;
  end;

implementation

uses
  Crypto4D.Bytes,
  Crypto4D.Ed25519;

class function TX509AlgorithmIdentifier.TryParse(const Element: TDerElement; out Algorithm: TX509AlgorithmIdentifier): Boolean;
begin
  Algorithm := Default(TX509AlgorithmIdentifier);
  const IsSequence = (Element.Tag = TDerTag.Sequence);
  if not IsSequence then
    Exit(False);

  var Reader := TDerReader.Create(Element.Content);
  var OidElement: TDerElement;
  var Oid: string;
  const HasOid = Reader.TryReadTagged(TDerTag.ObjectId, OidElement) and OidElement.TryGetObjectId(Oid);
  if not HasOid then
    Exit(False);

  var Parameters: TBytes := nil;
  if not Reader.IsAtEnd then
  begin
    var ParameterElement: TDerElement;
    const HasSingleParameter = Reader.TryRead(ParameterElement) and Reader.IsAtEnd;
    if not HasSingleParameter then
      Exit(False);
    Parameters := ParameterElement.Encoded;
  end;

  Algorithm.FOid        := Oid;
  Algorithm.FParameters := Parameters;
  Result                := True;
end;

function TX509AlgorithmIdentifier.HasNoParameters: Boolean;
begin
  Result := (Length(FParameters) = 0);
end;

function TX509AlgorithmIdentifier.HasNullOrNoParameters: Boolean;
begin
  const EncodedNull = TBytes.Create(TDerTag.Null, 0);
  Result := HasNoParameters or TByteArrays.AreEqual(FParameters, EncodedNull);
end;

function TX509AlgorithmIdentifier.IsSameAs(const Other: TX509AlgorithmIdentifier): Boolean;
begin
  Result := (FOid = Other.FOid) and TByteArrays.AreEqual(FParameters, Other.FParameters);
end;

class function TX509PublicKeyInfo.TryParse(const Der: TBytes; out PublicKey: TX509PublicKeyInfo): Boolean;
begin
  PublicKey := Default(TX509PublicKeyInfo);

  var Reader := TDerReader.Create(Der);
  var Element: TDerElement;
  if not Reader.TryReadOnly(TDerTag.Sequence, Element) then
    Exit(False);

  Result := TryParseElement(Element, PublicKey);
end;

class function TX509PublicKeyInfo.TryParseElement(const Element: TDerElement; out PublicKey: TX509PublicKeyInfo): Boolean;
begin
  PublicKey := Default(TX509PublicKeyInfo);
  const IsSequence = (Element.Tag = TDerTag.Sequence);
  if not IsSequence then
    Exit(False);

  var Reader := TDerReader.Create(Element.Content);
  var AlgorithmElement: TDerElement;
  var KeyElement: TDerElement;
  const HasBothParts = Reader.TryReadTagged(TDerTag.Sequence, AlgorithmElement) and
                       Reader.TryReadOnly(TDerTag.BitString, KeyElement);
  if not HasBothParts then
    Exit(False);

  var Algorithm: TX509AlgorithmIdentifier;
  var KeyBytes: TBytes;
  const IsWellFormed = TX509AlgorithmIdentifier.TryParse(AlgorithmElement, Algorithm) and
                       KeyElement.TryGetBitStringBytes(KeyBytes);
  if not IsWellFormed then
    Exit(False);

  PublicKey.FAlgorithm := Algorithm;
  PublicKey.FKeyBytes  := KeyBytes;
  PublicKey.FEncoded   := Element.Encoded;
  Result               := True;
end;

function TX509PublicKeyInfo.TryGetEcdsaP256Key(out Key: TEcdsaP256PublicKey): Boolean;
begin
  Key := Default(TEcdsaP256PublicKey);

  const Prime256v1Parameters = TBytes.Create(TDerTag.ObjectId, 8, $2A, $86, $48, $CE, $3D, $03, $01, $07);
  const IsP256Key = (FAlgorithm.Oid = TX509Oid.EcPublicKey) and
                    TByteArrays.AreEqual(FAlgorithm.Parameters, Prime256v1Parameters) and
                    TEcdsaP256PublicKey.IsUncompressedPoint(FKeyBytes);
  if not IsP256Key then
    Exit(False);

  Key    := TEcdsaP256PublicKey.FromUncompressedPoint(FKeyBytes);
  Result := True;
end;

function TX509PublicKeyInfo.TryGetRsaKey(out Key: TRsaPublicKey): Boolean;
begin
  Key := Default(TRsaPublicKey);

  const IsRsaKey = (FAlgorithm.Oid = TX509Oid.RsaEncryption) and FAlgorithm.HasNullOrNoParameters;
  if not IsRsaKey then
    Exit(False);

  var Outer := TDerReader.Create(FKeyBytes);
  var Sequence: TDerElement;
  if not Outer.TryReadOnly(TDerTag.Sequence, Sequence) then
    Exit(False);

  var Inner := TDerReader.Create(Sequence.Content);
  var ModulusElement: TDerElement;
  var ExponentElement: TDerElement;
  const HasTwoIntegers = Inner.TryReadTagged(TDerTag.Integer, ModulusElement) and
                         Inner.TryReadOnly(TDerTag.Integer, ExponentElement);
  if not HasTwoIntegers then
    Exit(False);

  var Modulus: TBytes;
  var Exponent: TBytes;
  const IsUsable = ModulusElement.TryGetUnsignedInteger(Modulus) and
                   ExponentElement.TryGetUnsignedInteger(Exponent) and
                   TRsaPublicKey.IsSupportedModulus(Modulus) and
                   TRsaPublicKey.IsSupportedExponent(Exponent);
  if not IsUsable then
    Exit(False);

  Key    := TRsaPublicKey.Create(Modulus, Exponent);
  Result := True;
end;

function TX509PublicKeyInfo.TryGetEd25519Key(out Key: TBytes): Boolean;
begin
  Key := nil;

  const IsEd25519Key = (FAlgorithm.Oid = TX509Oid.Ed25519) and
                       FAlgorithm.HasNoParameters and
                       (Length(FKeyBytes) = TEd25519.PublicKeySize);
  if not IsEd25519Key then
    Exit(False);

  Key    := Copy(FKeyBytes);
  Result := True;
end;

class function TX509Extension.TryParse(const Element: TDerElement; out Extension: TX509Extension): Boolean;
begin
  Extension := Default(TX509Extension);
  const IsSequence = (Element.Tag = TDerTag.Sequence);
  if not IsSequence then
    Exit(False);

  var Reader := TDerReader.Create(Element.Content);
  var OidElement: TDerElement;
  var Oid: string;
  const HasOid = Reader.TryReadTagged(TDerTag.ObjectId, OidElement) and OidElement.TryGetObjectId(Oid);
  if not HasOid then
    Exit(False);

  var Critical := False;
  var NextTag: Byte;
  const HasCriticalFlag = Reader.TryPeekTag(NextTag) and (NextTag = TDerTag.Boolean);
  if HasCriticalFlag then
  begin
    var CriticalElement: TDerElement;
    const IsExplicitTrue = Reader.TryRead(CriticalElement) and
                           CriticalElement.TryGetBoolean(Critical) and
                           Critical;
    if not IsExplicitTrue then
      Exit(False);
  end;

  var ValueElement: TDerElement;
  if not Reader.TryReadOnly(TDerTag.OctetString, ValueElement) then
    Exit(False);

  Extension.FOid      := Oid;
  Extension.FCritical := Critical;
  Extension.FValue    := ValueElement.Content;
  Result              := True;
end;

class function TX509Certificate.TryParse(const Der: TBytes; out Certificate: TX509Certificate): Boolean;
begin
  Certificate := Default(TX509Certificate);

  var Outer := TDerReader.Create(Der);
  var CertificateElement: TDerElement;
  if not Outer.TryReadOnly(TDerTag.Sequence, CertificateElement) then
    Exit(False);

  var Reader := TDerReader.Create(CertificateElement.Content);
  var TbsElement: TDerElement;
  var AlgorithmElement: TDerElement;
  var SignatureElement: TDerElement;
  const HasThreeParts = Reader.TryReadTagged(TDerTag.Sequence, TbsElement) and
                        Reader.TryReadTagged(TDerTag.Sequence, AlgorithmElement) and
                        Reader.TryReadOnly(TDerTag.BitString, SignatureElement);
  if not HasThreeParts then
    Exit(False);

  var Parsed := Default(TX509Certificate);
  Parsed.FTbsCertificate := TbsElement.Encoded;
  const IsWellFormed = TX509AlgorithmIdentifier.TryParse(AlgorithmElement, Parsed.FSignatureAlgorithm) and
                       SignatureElement.TryGetBitStringBytes(Parsed.FSignature) and
                       Parsed.TryParseTbsCertificate(TbsElement.Content);
  if not IsWellFormed then
    Exit(False);

  Certificate := Parsed;
  Result      := True;
end;

function TX509Certificate.TryParseTbsCertificate(const Content: TBytes): Boolean;
begin
  var Reader := TDerReader.Create(Content);
  if not TryReadVersion(Reader) then
    Exit(False);

  var SerialElement: TDerElement;
  var AlgorithmElement: TDerElement;
  const HasSerialAndAlgorithm = Reader.TryReadTagged(TDerTag.Integer, SerialElement) and
                                (Length(SerialElement.Content) > 0) and
                                Reader.TryReadTagged(TDerTag.Sequence, AlgorithmElement) and
                                TX509AlgorithmIdentifier.TryParse(AlgorithmElement, FTbsSignatureAlgorithm);
  if not HasSerialAndAlgorithm then
    Exit(False);
  FSerialNumber := SerialElement.Content;

  if not TryReadNames(Reader) then
    Exit(False);

  var PublicKeyElement: TDerElement;
  const HasPublicKey = Reader.TryReadTagged(TDerTag.Sequence, PublicKeyElement) and
                       TX509PublicKeyInfo.TryParseElement(PublicKeyElement, FPublicKey);
  if not HasPublicKey then
    Exit(False);

  Result := TryReadOptionalFields(Reader) and Reader.IsAtEnd;
end;

function TX509Certificate.TryReadVersion(var Reader: TDerReader): Boolean;
begin
  FVersion := DefaultVersion;

  var NextTag: Byte;
  const VersionTag = TDerTag.ContextSpecific or TDerTag.Constructed or VersionTagNumber;
  const HasVersion = Reader.TryPeekTag(NextTag) and (NextTag = VersionTag);
  if not HasVersion then
    Exit(True);

  var Wrapper: TDerElement;
  if not Reader.TryRead(Wrapper) then
    Exit(False);

  var Inner := TDerReader.Create(Wrapper.Content);
  var VersionElement: TDerElement;
  var VersionBytes: TBytes;
  const HasSingleByte = Inner.TryReadOnly(TDerTag.Integer, VersionElement) and
                        VersionElement.TryGetUnsignedInteger(VersionBytes) and
                        (Length(VersionBytes) = 1);
  if not HasSingleByte then
    Exit(False);

  FVersion := VersionBytes[0] + 1;
  Result   := (FVersion <= HighestVersion);
end;

function TX509Certificate.TryReadNames(var Reader: TDerReader): Boolean;
begin
  var IssuerElement: TDerElement;
  var ValidityElement: TDerElement;
  var SubjectElement: TDerElement;
  Result := Reader.TryReadTagged(TDerTag.Sequence, IssuerElement) and
            Reader.TryReadTagged(TDerTag.Sequence, ValidityElement) and
            Reader.TryReadTagged(TDerTag.Sequence, SubjectElement);
  if not Result then
    Exit;

  FIssuer   := IssuerElement.Encoded;
  FValidity := ValidityElement.Encoded;
  FSubject  := SubjectElement.Encoded;
end;

function TX509Certificate.TryReadOptionalFields(var Reader: TDerReader): Boolean;
begin
  Result := TrySkipUniqueId(Reader, IssuerIdTagNumber) and
            TrySkipUniqueId(Reader, SubjectIdTagNumber) and
            TryReadExtensions(Reader);
end;

function TX509Certificate.TrySkipUniqueId(var Reader: TDerReader; const TagNumber: Byte): Boolean;
begin
  var NextTag: Byte;
  const UniqueIdTag = PrimitiveContext or TagNumber;
  const IsPresent   = Reader.TryPeekTag(NextTag) and (NextTag = UniqueIdTag);
  if not IsPresent then
    Exit(True);

  var UniqueId: TDerElement;
  Result := Reader.TryRead(UniqueId);
end;

function TX509Certificate.TryReadExtensions(var Reader: TDerReader): Boolean;
begin
  FExtensions := nil;
  if Reader.IsAtEnd then
    Exit(True);

  var Wrapper: TDerElement;
  const HasWrapper = Reader.TryRead(Wrapper) and Wrapper.IsContextSpecific(ExtensionsTagNumber);
  if not HasWrapper then
    Exit(False);

  var Inner := TDerReader.Create(Wrapper.Content);
  var List: TDerElement;
  Result := Inner.TryReadOnly(TDerTag.Sequence, List) and TryParseExtensionList(List.Content);
end;

function TX509Certificate.TryParseExtensionList(const Content: TBytes): Boolean;
begin
  var Reader := TDerReader.Create(Content);
  if Reader.IsAtEnd then
    Exit(False);

  while not Reader.IsAtEnd do
  begin
    var Element: TDerElement;
    var Extension: TX509Extension;
    const IsNewExtension = Reader.TryRead(Element) and
                           TX509Extension.TryParse(Element, Extension) and
                           not HasExtension(Extension.Oid);
    if not IsNewExtension then
      Exit(False);

    FExtensions := FExtensions + [Extension];
  end;

  Result := True;
end;

function TX509Certificate.HasExtension(const Oid: string): Boolean;
begin
  var Extension: TX509Extension;
  Result := TryFindExtension(Oid, Extension);
end;

function TX509Certificate.TryFindExtension(const Oid: string; out Extension: TX509Extension): Boolean;
begin
  for var Candidate in FExtensions do
  begin
    const IsWanted = (Candidate.Oid = Oid);
    if IsWanted then
    begin
      Extension := Candidate;
      Exit(True);
    end;
  end;

  Extension := Default(TX509Extension);
  Result    := False;
end;

function TX509Certificate.IsSignedBy(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  const AlgorithmsAgree = FSignatureAlgorithm.IsSameAs(FTbsSignatureAlgorithm);
  if not AlgorithmsAgree then
    Exit(False);

  const SignatureOid = FSignatureAlgorithm.Oid;
  const IsEcdsa      = (SignatureOid = TX509Oid.EcdsaWithSha256);
  const IsRsa        = (SignatureOid = TX509Oid.Sha256WithRsa);
  const IsEd25519    = (SignatureOid = TX509Oid.Ed25519);

  if IsEcdsa then
    Result := VerifyEcdsa(IssuerKey)
  else if IsRsa then
    Result := VerifyRsa(IssuerKey)
  else if IsEd25519 then
    Result := VerifyEd25519(IssuerKey)
  else
    Result := False;
end;

function TX509Certificate.VerifyEcdsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  var Key: TEcdsaP256PublicKey;
  const CanVerify = FSignatureAlgorithm.HasNoParameters and IssuerKey.TryGetEcdsaP256Key(Key);
  if not CanVerify then
    Exit(False);

  Result := TEcdsaP256.VerifyDer(Key, FTbsCertificate, FSignature);
end;

function TX509Certificate.VerifyRsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  var Key: TRsaPublicKey;
  const CanVerify = FSignatureAlgorithm.HasNullOrNoParameters and IssuerKey.TryGetRsaKey(Key);
  if not CanVerify then
    Exit(False);

  Result := TRsaPkcs1Sha256.Verify(Key, FTbsCertificate, FSignature);
end;

function TX509Certificate.VerifyEd25519(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  var Key: TBytes;
  const CanVerify = FSignatureAlgorithm.HasNoParameters and IssuerKey.TryGetEd25519Key(Key);
  if not CanVerify then
    Exit(False);

  Result := TEd25519.Verify(Key, FTbsCertificate, FSignature);
end;

end.
