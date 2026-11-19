unit Crypto4D.X509;

interface

uses
  System.SysUtils,
  Crypto4D.Der,
  Crypto4D.Ecdsa,
  Crypto4D.Rsa;

type
  /// <summary>
  ///   Object identifiers of the algorithms that Crypto4D supports, in dotted notation.
  /// </summary>
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

  /// <summary>
  ///   An AlgorithmIdentifier: an object identifier with optional parameters.
  /// </summary>
  TX509AlgorithmIdentifier = record
  private
    FOid: string;
    FParameters: TBytes;

  public
    /// <summary>
    ///   Reads an AlgorithmIdentifier from a DER element.
    /// </summary>
    /// <param name="Element">The SEQUENCE element.</param>
    /// <param name="Algorithm">Receives the result.</param>
    /// <returns>False when Element is not a SEQUENCE of an OBJECT IDENTIFIER followed by at most one
    ///   element.</returns>
    class function TryParse(const Element: TDerElement; out Algorithm: TX509AlgorithmIdentifier): Boolean; static;

    /// <summary>
    ///   True when the parameters are absent.
    /// </summary>
    function HasNoParameters: Boolean;

    /// <summary>
    ///   True when the parameters are absent or an ASN.1 NULL.
    /// </summary>
    function HasNullOrNoParameters: Boolean;

    /// <summary>
    ///   True when Other has the same object identifier and the same encoded parameters.
    /// </summary>
    function IsSameAs(const Other: TX509AlgorithmIdentifier): Boolean;

    /// <summary>
    ///   The object identifier in dotted notation.
    /// </summary>
    property Oid: string read FOid;

    /// <summary>
    ///   DER encoding of the parameters element, or empty when the parameters are absent.
    /// </summary>
    property Parameters: TBytes read FParameters;
  end;

  /// <summary>
  ///   A SubjectPublicKeyInfo: the algorithm of a public key and the key itself.
  /// </summary>
  TX509PublicKeyInfo = record
  private
    FAlgorithm: TX509AlgorithmIdentifier;
    FKeyBytes: TBytes;
    FEncoded: TBytes;

    class function TryParseElement(const Element: TDerElement; out PublicKey: TX509PublicKeyInfo): Boolean; static;

  public
    /// <summary>
    ///   Parses a DER encoded SubjectPublicKeyInfo, which is also the content of a PEM block "PUBLIC KEY".
    /// </summary>
    /// <param name="Der">The complete DER encoding, without anything after it.</param>
    /// <param name="PublicKey">Receives the result.</param>
    /// <returns>False when Der is not strict DER or not a SubjectPublicKeyInfo. The key itself is not checked
    ///   here.</returns>
    class function TryParse(const Der: TBytes; out PublicKey: TX509PublicKeyInfo): Boolean; static;

    /// <summary>
    ///   Converts the key to an ECDSA key on P-256.
    /// </summary>
    /// <param name="Key">Receives the key.</param>
    /// <returns>False when the algorithm is not id-ecPublicKey with the curve prime256v1, or the key is not an
    ///   uncompressed point of 65 bytes. Whether the point is on the curve is checked when a signature is
    ///   verified.</returns>
    function TryGetEcdsaP256Key(out Key: TEcdsaP256PublicKey): Boolean;

    /// <summary>
    ///   Converts the key to an RSA key.
    /// </summary>
    /// <param name="Key">Receives the key.</param>
    /// <returns>False when the algorithm is not rsaEncryption with absent or NULL parameters, the key is not a DER
    ///   encoded RSAPublicKey, or modulus or exponent is outside the limits of TRsaPublicKey.Create.</returns>
    function TryGetRsaKey(out Key: TRsaPublicKey): Boolean;

    /// <summary>
    ///   Returns the Ed25519 key.
    /// </summary>
    /// <param name="Key">Receives the encoded public key, 32 bytes.</param>
    /// <returns>False when the algorithm is not Ed25519 without parameters or the key is not 32 bytes.</returns>
    function TryGetEd25519Key(out Key: TBytes): Boolean;

    /// <summary>
    ///   The algorithm of the key.
    /// </summary>
    property Algorithm: TX509AlgorithmIdentifier read FAlgorithm;

    /// <summary>
    ///   Content of the subjectPublicKey BIT STRING.
    /// </summary>
    property KeyBytes: TBytes read FKeyBytes;

    /// <summary>
    ///   DER encoding of the whole SubjectPublicKeyInfo.
    /// </summary>
    property Encoded: TBytes read FEncoded;
  end;

  /// <summary>
  ///   One certificate extension. The value is not interpreted.
  /// </summary>
  TX509Extension = record
  private
    FOid: string;
    FCritical: Boolean;
    FValue: TBytes;

  public
    /// <summary>
    ///   Reads an Extension from a DER element.
    /// </summary>
    /// <param name="Element">The SEQUENCE element.</param>
    /// <param name="Extension">Receives the result.</param>
    /// <returns>False when Element is not a SEQUENCE of an OBJECT IDENTIFIER, an optional BOOLEAN and an OCTET
    ///   STRING, or when the BOOLEAN is present with the value FALSE, which DER does not allow for a default
    ///   value.</returns>
    class function TryParse(const Element: TDerElement; out Extension: TX509Extension): Boolean; static;

    /// <summary>
    ///   The object identifier of the extension in dotted notation.
    /// </summary>
    property Oid: string read FOid;

    /// <summary>
    ///   True when the extension is marked critical.
    /// </summary>
    property Critical: Boolean read FCritical;

    /// <summary>
    ///   Content of the extnValue OCTET STRING, which is the DER encoding of the extension value.
    /// </summary>
    property Value: TBytes read FValue;
  end;

  /// <summary>
  ///   The fields of a parsed X.509 certificate. Crypto4D does not validate a chain: it has no trust store and it
  ///   does not look at validity dates, key usage, names or revocation.
  /// </summary>
  TX509CertificateInfo = record
  private
    const
      VersionTagNumber    = 0;
      IssuerIdTagNumber   = 1;
      SubjectIdTagNumber  = 2;
      ExtensionsTagNumber = 3;
      DefaultVersion      = 1;
      UniqueIdVersion     = 2;
      HighestVersion      = 3;
      PrimitiveContext    = $80;
      SmallestExtension   = 7;

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
    function HasDuplicateExtension: Boolean;
    class function SortedOids(const Oids: TArray<string>): TArray<string>; static;
    class function MergedOids(const Lower, Upper: TArray<string>): TArray<string>; static;
    function VerifyEcdsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
    function VerifyRsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
    function VerifyEd25519(const IssuerKey: TX509PublicKeyInfo): Boolean;

  public
    /// <summary>
    ///   Parses a DER encoded certificate.
    /// </summary>
    /// <param name="Der">The complete DER encoding, without anything after it. For a PEM file, decode the Base64
    ///   first.</param>
    /// <param name="Certificate">Receives the result.</param>
    /// <returns>False when Der is not strict DER or not a certificate: a field is missing or out of order, the
    ///   version is above 3 or is 1 in explicit form, the serial number is not in its shortest encoding, a unique
    ///   identifier appears in a version 1 certificate, extensions appear in a certificate that is not version 3,
    ///   the list of extensions is empty or names an extension twice. Issuer, validity and subject are kept as they
    ///   are; their content is not parsed.</returns>
    class function TryParse(const Der: TBytes; out Certificate: TX509CertificateInfo): Boolean; static;

    /// <summary>
    ///   Looks up an extension by its object identifier.
    /// </summary>
    /// <param name="Oid">Object identifier in dotted notation, such as 2.5.29.19.</param>
    /// <param name="Extension">Receives the extension.</param>
    /// <returns>False when the certificate has no such extension.</returns>
    function TryFindExtension(const Oid: string; out Extension: TX509Extension): Boolean;

    /// <summary>
    ///   Checks the signature of the certificate with a given public key.
    /// </summary>
    /// <param name="IssuerKey">Public key of the issuer, for example the PublicKey of the issuer
    ///   certificate.</param>
    /// <returns>True when the signature over TbsCertificate is valid for IssuerKey. False when the two signature
    ///   algorithm identifiers of the certificate differ in object identifier or in parameters, the algorithm is
    ///   not ecdsa-with-SHA256, sha256WithRSAEncryption or Ed25519, the parameters are something else than absent
    ///   or NULL for ecdsa-with-SHA256 and sha256WithRSAEncryption or are present for Ed25519, IssuerKey is not a
    ///   key for that algorithm, or the signature does not match.</returns>
    function IsSignedBy(const IssuerKey: TX509PublicKeyInfo): Boolean;

    /// <summary>
    ///   DER encoding of tbsCertificate, the part that is signed.
    /// </summary>
    property TbsCertificate: TBytes read FTbsCertificate;

    /// <summary>
    ///   Certificate version: 1, 2 or 3.
    /// </summary>
    property Version: Integer read FVersion;

    /// <summary>
    ///   Content of the serialNumber INTEGER: two's complement, most significant byte first.
    /// </summary>
    property SerialNumber: TBytes read FSerialNumber;

    /// <summary>
    ///   The signature algorithm as stated inside tbsCertificate.
    /// </summary>
    property TbsSignatureAlgorithm: TX509AlgorithmIdentifier read FTbsSignatureAlgorithm;

    /// <summary>
    ///   DER encoding of the issuer name.
    /// </summary>
    property Issuer: TBytes read FIssuer;

    /// <summary>
    ///   DER encoding of the validity SEQUENCE.
    /// </summary>
    property Validity: TBytes read FValidity;

    /// <summary>
    ///   DER encoding of the subject name.
    /// </summary>
    property Subject: TBytes read FSubject;

    /// <summary>
    ///   The public key of the subject.
    /// </summary>
    property PublicKey: TX509PublicKeyInfo read FPublicKey;

    /// <summary>
    ///   The extensions in the order of the certificate; empty when there are none.
    /// </summary>
    property Extensions: TArray<TX509Extension> read FExtensions;

    /// <summary>
    ///   The signature algorithm as stated outside tbsCertificate.
    /// </summary>
    property SignatureAlgorithm: TX509AlgorithmIdentifier read FSignatureAlgorithm;

    /// <summary>
    ///   Content of the signatureValue BIT STRING.
    /// </summary>
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

class function TX509CertificateInfo.TryParse(const Der: TBytes; out Certificate: TX509CertificateInfo): Boolean;
begin
  Certificate := Default(TX509CertificateInfo);

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

  var Parsed := Default(TX509CertificateInfo);
  Parsed.FTbsCertificate := TbsElement.Encoded;
  const IsWellFormed = TX509AlgorithmIdentifier.TryParse(AlgorithmElement, Parsed.FSignatureAlgorithm) and
                       SignatureElement.TryGetBitStringBytes(Parsed.FSignature) and
                       Parsed.TryParseTbsCertificate(TbsElement.Content);
  if not IsWellFormed then
    Exit(False);

  Certificate := Parsed;
  Result      := True;
end;

function TX509CertificateInfo.TryParseTbsCertificate(const Content: TBytes): Boolean;
begin
  var Reader := TDerReader.Create(Content);
  if not TryReadVersion(Reader) then
    Exit(False);

  var SerialElement: TDerElement;
  var AlgorithmElement: TDerElement;
  const HasSerialAndAlgorithm = Reader.TryReadTagged(TDerTag.Integer, SerialElement) and
                                SerialElement.TryGetInteger(FSerialNumber) and
                                Reader.TryReadTagged(TDerTag.Sequence, AlgorithmElement) and
                                TX509AlgorithmIdentifier.TryParse(AlgorithmElement, FTbsSignatureAlgorithm);
  if not HasSerialAndAlgorithm then
    Exit(False);

  if not TryReadNames(Reader) then
    Exit(False);

  var PublicKeyElement: TDerElement;
  const HasPublicKey = Reader.TryReadTagged(TDerTag.Sequence, PublicKeyElement) and
                       TX509PublicKeyInfo.TryParseElement(PublicKeyElement, FPublicKey);
  if not HasPublicKey then
    Exit(False);

  Result := TryReadOptionalFields(Reader) and Reader.IsAtEnd;
end;

function TX509CertificateInfo.TryReadVersion(var Reader: TDerReader): Boolean;
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
  Result   := (FVersion > DefaultVersion) and (FVersion <= HighestVersion);
end;

function TX509CertificateInfo.TryReadNames(var Reader: TDerReader): Boolean;
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

function TX509CertificateInfo.TryReadOptionalFields(var Reader: TDerReader): Boolean;
begin
  Result := TrySkipUniqueId(Reader, IssuerIdTagNumber) and
            TrySkipUniqueId(Reader, SubjectIdTagNumber) and
            TryReadExtensions(Reader);
end;

function TX509CertificateInfo.TrySkipUniqueId(var Reader: TDerReader; const TagNumber: Byte): Boolean;
begin
  var NextTag: Byte;
  const UniqueIdTag = PrimitiveContext or TagNumber;
  const IsPresent   = Reader.TryPeekTag(NextTag) and (NextTag = UniqueIdTag);
  if not IsPresent then
    Exit(True);

  var UniqueId: TDerElement;
  Result := (FVersion >= UniqueIdVersion) and Reader.TryRead(UniqueId) and UniqueId.HasBitStringContent;
end;

function TX509CertificateInfo.TryReadExtensions(var Reader: TDerReader): Boolean;
begin
  FExtensions := nil;
  if Reader.IsAtEnd then
    Exit(True);

  var Wrapper: TDerElement;
  const HasWrapper = (FVersion = HighestVersion) and
                     Reader.TryRead(Wrapper) and
                     Wrapper.IsContextSpecific(ExtensionsTagNumber);
  if not HasWrapper then
    Exit(False);

  var Inner := TDerReader.Create(Wrapper.Content);
  var List: TDerElement;
  Result := Inner.TryReadOnly(TDerTag.Sequence, List) and TryParseExtensionList(List.Content);
end;

function TX509CertificateInfo.TryParseExtensionList(const Content: TBytes): Boolean;
begin
  var Reader := TDerReader.Create(Content);
  if Reader.IsAtEnd then
    Exit(False);

  var Parsed: TArray<TX509Extension>;
  SetLength(Parsed, Length(Content) div SmallestExtension);
  var Count := 0;

  while not Reader.IsAtEnd do
  begin
    var Element: TDerElement;
    var Extension: TX509Extension;
    const IsExtension = Reader.TryRead(Element) and TX509Extension.TryParse(Element, Extension);
    if not IsExtension then
      Exit(False);

    Parsed[Count] := Extension;
    Inc(Count);
  end;

  FExtensions := Copy(Parsed, 0, Count);
  Result      := not HasDuplicateExtension;
end;

function TX509CertificateInfo.HasDuplicateExtension: Boolean;
begin
  var Oids: TArray<string>;
  SetLength(Oids, Length(FExtensions));
  for var Index := 0 to High(FExtensions) do
  begin
    Oids[Index] := FExtensions[Index].Oid;
  end;
  const Sorted = SortedOids(Oids);

  for var Index := 1 to High(Sorted) do
  begin
    const RepeatsPrevious = (Sorted[Index] = Sorted[Index - 1]);
    if RepeatsPrevious then
      Exit(True);
  end;

  Result := False;
end;

class function TX509CertificateInfo.SortedOids(const Oids: TArray<string>): TArray<string>;
begin
  const Count          = Length(Oids);
  const NeedsNoSorting = (Count <= 1);
  if NeedsNoSorting then
    Exit(Oids);

  const Middle    = Count div 2;
  const LowerHalf = Copy(Oids, 0, Middle);
  const UpperHalf = Copy(Oids, Middle, Count - Middle);
  const Lower     = SortedOids(LowerHalf);
  const Upper     = SortedOids(UpperHalf);

  Result := MergedOids(Lower, Upper);
end;

class function TX509CertificateInfo.MergedOids(const Lower, Upper: TArray<string>): TArray<string>;
begin
  SetLength(Result, Length(Lower) + Length(Upper));
  var LowerIndex := 0;
  var UpperIndex := 0;

  for var Index := 0 to High(Result) do
  begin
    const LowerIsDone = (LowerIndex = Length(Lower));
    const UpperIsDone = (UpperIndex = Length(Upper));
    const TakesLower  = UpperIsDone or
                        ((not LowerIsDone) and (CompareStr(Lower[LowerIndex], Upper[UpperIndex]) <= 0));
    if TakesLower then
    begin
      Result[Index] := Lower[LowerIndex];
      Inc(LowerIndex);
    end
    else
    begin
      Result[Index] := Upper[UpperIndex];
      Inc(UpperIndex);
    end;
  end;
end;

function TX509CertificateInfo.TryFindExtension(const Oid: string; out Extension: TX509Extension): Boolean;
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

function TX509CertificateInfo.IsSignedBy(const IssuerKey: TX509PublicKeyInfo): Boolean;
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

function TX509CertificateInfo.VerifyEcdsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  var Key: TEcdsaP256PublicKey;
  const CanVerify = FSignatureAlgorithm.HasNullOrNoParameters and IssuerKey.TryGetEcdsaP256Key(Key);
  if not CanVerify then
    Exit(False);

  Result := TEcdsaP256.VerifyDer(Key, FTbsCertificate, FSignature);
end;

function TX509CertificateInfo.VerifyRsa(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  var Key: TRsaPublicKey;
  const CanVerify = FSignatureAlgorithm.HasNullOrNoParameters and IssuerKey.TryGetRsaKey(Key);
  if not CanVerify then
    Exit(False);

  Result := TRsaPkcs1Sha256.Verify(Key, FTbsCertificate, FSignature);
end;

function TX509CertificateInfo.VerifyEd25519(const IssuerKey: TX509PublicKeyInfo): Boolean;
begin
  var Key: TBytes;
  const CanVerify = FSignatureAlgorithm.HasNoParameters and IssuerKey.TryGetEd25519Key(Key);
  if not CanVerify then
    Exit(False);

  Result := TEd25519.Verify(Key, FTbsCertificate, FSignature);
end;

end.
