unit Crypto4D.X509.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework,
  Crypto4D.X509;

type
  [TestFixture]
  TX509Tests = class
  private
    const
      Folder               = 'x509/';
      ManifestFile         = 'x509/manifest.json';
      P256File             = 'p256.der';
      RsaFile              = 'rsa2048.der';
      Ed25519File          = 'ed25519.der';
      LeafFile             = 'leaf_ed25519_signed_by_p256.der';
      SubjectKeyIdOid      = '2.5.29.14';
      BasicConstraintsOid  = '2.5.29.19';
      UnknownOid           = '1.2.3.4';
      SequenceTag          = $30;
      OuterHeaderSize      = 4;
      KeyIdentifierSize    = 22;
      AlgorithmName        = 'signatureAlgorithm';
      BitStringTag         = $03;
      OctetStringTag       = $04;
      ObjectIdTag          = $06;
      ExtensionsTag        = $A3;
      Ed25519AlgorithmHex  = '300506032b6570';
      RsaAlgorithmHex      = '300d06092a864886f70d0101010500';
      IntegerTag           = $02;
      RsaModulusSize       = 256;
      HighestBitOfByte     = $80;
      VersionOneHex        = 'a003020100';
      VersionTwoHex        = 'a003020101';
      VersionThreeHex      = 'a003020102';
      SerialOneHex         = '020101';
      FirstExtensionArc    = 16384;
      KeySize              = 32;
      SignatureSize        = 64;
      ManyExtensions       = 80000;
      TimeLimitMs          = 5000;

    var
      FManifest: TJSONObject;

    function Load(const FileName: string): TBytes;
    function Parse(const FileName: string): TX509CertificateInfo;
    function ManifestEntry(const FileName: string): TJSONObject;
    function Bytes(const Hex: string): TBytes;
    function BitString(const Content: TBytes): TBytes;
    function Extension(const Number: Integer): TBytes;
    function ExtensionList(const Extensions: TBytes): TBytes;
    function RsaKeyInfo(const LowestModulusByte: Byte; const ExponentHex: string): TBytes;
    function CraftedCertificate(const VersionHex, SerialHex: string; const OptionalFields: TBytes): TBytes;
    function Parses(const Der: TBytes): Boolean;

  public
    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    [Test]
    [TestCase('P256', 'p256.der')]
    [TestCase('Rsa2048', 'rsa2048.der')]
    [TestCase('Ed25519', 'ed25519.der')]
    [TestCase('Leaf', 'leaf_ed25519_signed_by_p256.der')]
    procedure TryParse_OpenSslCertificate_MatchesOpenSslReport(const FileName: string);

    [Test]
    [TestCase('P256', 'p256.der')]
    [TestCase('Rsa2048', 'rsa2048.der')]
    [TestCase('Ed25519', 'ed25519.der')]
    [TestCase('Leaf', 'leaf_ed25519_signed_by_p256.der')]
    procedure IsSignedBy_IssuerKey_ReturnsTrue(const FileName: string);

    [Test]
    procedure IsSignedBy_OwnKeyOfLeaf_ReturnsFalse;

    [Test]
    [TestCase('P256ByRsa', 'p256.der,rsa2048.der')]
    [TestCase('RsaByEd25519', 'rsa2048.der,ed25519.der')]
    [TestCase('Ed25519ByP256', 'ed25519.der,p256.der')]
    procedure IsSignedBy_KeyOfOtherAlgorithm_ReturnsFalse(const FileName: string; const OtherFileName: string);

    [Test]
    [TestCase('NullInBoth', 'p256_null_parameter.der,True')]
    [TestCase('NullInTbsCertificateOnly', 'p256_null_parameter_inner_only.der,False')]
    [TestCase('NullOutsideTbsCertificateOnly', 'p256_null_parameter_outer_only.der,False')]
    [TestCase('EmptySequenceInBoth', 'p256_sequence_parameter.der,False')]
    procedure IsSignedBy_EcdsaAlgorithmWithParameter_AcceptsNullInBothOnly(const FileName: string; const Expected: Boolean);

    [Test]
    [TestCase('P256', 'p256.der')]
    [TestCase('Rsa2048', 'rsa2048.der')]
    [TestCase('Ed25519', 'ed25519.der')]
    procedure TryParse_OneBitFlippedPerByte_NeverVerifiesAndNeverRaises(const FileName: string);

    [Test]
    [TestCase('P256', 'p256.der')]
    [TestCase('Rsa2048', 'rsa2048.der')]
    [TestCase('Ed25519', 'ed25519.der')]
    procedure TryParse_AnyTruncation_ReturnsFalse(const FileName: string);

    [Test]
    procedure TryParse_TrailingByte_ReturnsFalse;

    [Test]
    procedure TryParse_Empty_ReturnsFalse;

    [Test]
    procedure TryParse_CraftedCertificateWithExtension_ReturnsTrue;

    [Test]
    procedure TryParse_ExplicitDefaultVersion_ReturnsFalse;

    [Test]
    [TestCase('Positive', '020101,True')]
    [TestCase('NeedsSignByte', '02020080,True')]
    [TestCase('Negative', '020180,True')]
    [TestCase('NegativeTwoBytes', '0202ff7f,True')]
    [TestCase('Empty', '0200,False')]
    [TestCase('RedundantZero', '0202007f,False')]
    [TestCase('RedundantOnes', '0202ff80,False')]
    procedure TryParse_SerialNumberEncoding_AcceptsMinimalOnly(const SerialHex: string; const Expected: Boolean);

    [Test]
    [TestCase('VersionOneWithUniqueId', ',810200aa,False')]
    [TestCase('VersionTwoWithUniqueId', 'a003020101,810200aa,True')]
    [TestCase('VersionThreeWithBothUniqueIds', 'a003020102,810200aa820200bb,True')]
    [TestCase('SubjectIdBeforeIssuerId', 'a003020102,820200bb810200aa,False')]
    procedure TryParse_UniqueIdentifiers_NeedVersionTwo(const VersionHex: string; const FieldsHex: string; const Expected: Boolean);

    [Test]
    [TestCase('VersionOne', ',False')]
    [TestCase('VersionTwo', 'a003020101,False')]
    [TestCase('VersionThree', 'a003020102,True')]
    procedure TryParse_Extensions_NeedVersionThree(const VersionHex: string; const Expected: Boolean);

    [Test]
    [TestCase('NoUnusedBits', '810200aa,True')]
    [TestCase('UnusedBitsAreZero', '810203a8,True')]
    [TestCase('EmptyBitString', '810100,True')]
    [TestCase('NoContent', '8100,False')]
    [TestCase('UnusedBitsWithoutData', '810101,False')]
    [TestCase('EightUnusedBits', '810208aa,False')]
    [TestCase('UnusedBitsAreSet', '810203ac,False')]
    procedure TryParse_UniqueIdentifierEncoding_AcceptsDerBitStringOnly(const UniqueIdHex: string; const Expected: Boolean);

    [Test]
    procedure TryParse_DuplicateExtension_ReturnsFalse;

    [Test]
    procedure TryParse_EmptyExtensionList_ReturnsFalse;

    [Test]
    procedure TryParse_ManyExtensions_FinishesWithinTimeLimit;

    [Test]
    procedure TbsCertificate_OfParsedCertificate_IsFirstElementOfCertificate;

    [Test]
    procedure TryFindExtension_PresentExtension_ReturnsValue;

    [Test]
    procedure TryFindExtension_CriticalExtension_ReportsCritical;

    [Test]
    procedure TryFindExtension_AbsentExtension_ReturnsFalse;

    [Test]
    procedure PublicKeyInfoTryParse_Garbage_ReturnsFalse;

    [Test]
    procedure TryGetKey_OtherAlgorithm_ReturnsFalse;

    [Test]
    [TestCase('SmallestModulusAndCommonExponent', '1,010001,True')]
    [TestCase('LargestExponent', '1,01ffffffff,True')]
    [TestCase('EvenModulus', '0,010001,False')]
    [TestCase('EvenExponent', '1,010000,False')]
    [TestCase('ExponentTooLarge', '1,0200000001,False')]
    procedure TryGetRsaKey_KeyLimits_AcceptsSupportedKeysOnly(const LowestModulusByte: Byte;
                                                              const ExponentHex: string;
                                                              const Expected: Boolean);
  end;

implementation

uses
  System.Diagnostics,
  Crypto4D.Ecdsa,
  Crypto4D.Rsa,
  Crypto4D.TestSupport;

procedure TX509Tests.SetupFixture;
begin
  FManifest := TTestSupport.LoadJsonObject(ManifestFile);
end;

procedure TX509Tests.TearDownFixture;
begin
  FManifest.Free;
end;

function TX509Tests.Load(const FileName: string): TBytes;
begin
  Result := TTestSupport.LoadBytes(Folder + FileName);
end;

function TX509Tests.Parse(const FileName: string): TX509CertificateInfo;
begin
  const Der    = Load(FileName);
  const Parsed = TX509CertificateInfo.TryParse(Der, Result);
  Assert.IsTrue(Parsed, FileName);
end;

function TX509Tests.ManifestEntry(const FileName: string): TJSONObject;
begin
  const Certificates = TTestSupport.ArrayOf(FManifest, 'certificates');
  for var Item in Certificates do
  begin
    const Entry    = Item as TJSONObject;
    const IsWanted = (Entry.GetValue<string>('file') = FileName);
    if IsWanted then
      Exit(Entry);
  end;

  raise ETestSupportError.CreateFmt('Certificate "%s" is not in the manifest', [FileName]);
end;

function TX509Tests.Bytes(const Hex: string): TBytes;
begin
  Result := TTestSupport.HexToBytes(Hex);
end;

function TX509Tests.BitString(const Content: TBytes): TBytes;
begin
  const NoUnusedBits = TBytes.Create(0);
  Result := TTestSupport.DerElement(BitStringTag, NoUnusedBits + Content);
end;

function TX509Tests.Extension(const Number: Integer): TBytes;
begin
  const LastArc    = FirstExtensionArc + Number;
  const LowArc     = Byte(LastArc and $7F);
  const MiddleArc  = Byte(((LastArc shr 7) and $7F) or $80);
  const HighArc    = Byte(((LastArc shr 14) and $7F) or $80);
  const Arcs       = TBytes.Create($2A, $03, HighArc, MiddleArc, LowArc);
  const ObjectId   = TTestSupport.DerElement(ObjectIdTag, Arcs);
  const EmptyValue = TTestSupport.DerElement(OctetStringTag, nil);

  Result := TTestSupport.DerElement(SequenceTag, ObjectId + EmptyValue);
end;

function TX509Tests.ExtensionList(const Extensions: TBytes): TBytes;
begin
  const List = TTestSupport.DerElement(SequenceTag, Extensions);
  Result := TTestSupport.DerElement(ExtensionsTag, List);
end;

function TX509Tests.RsaKeyInfo(const LowestModulusByte: Byte; const ExponentHex: string): TBytes;
begin
  var Modulus: TBytes;
  SetLength(Modulus, RsaModulusSize);
  Modulus[0]                  := HighestBitOfByte;
  Modulus[RsaModulusSize - 1] := LowestModulusByte;

  const SignByte      = TBytes.Create(0);
  const Exponent      = Bytes(ExponentHex);
  const ModulusValue  = TTestSupport.DerElement(IntegerTag, SignByte + Modulus);
  const ExponentValue = TTestSupport.DerElement(IntegerTag, Exponent);
  const RsaPublicKey  = TTestSupport.DerElement(SequenceTag, ModulusValue + ExponentValue);
  const Algorithm     = Bytes(RsaAlgorithmHex);
  const KeyBits       = BitString(RsaPublicKey);

  Result := TTestSupport.DerElement(SequenceTag, Algorithm + KeyBits);
end;

function TX509Tests.CraftedCertificate(const VersionHex, SerialHex: string; const OptionalFields: TBytes): TBytes;
begin
  var Key: TBytes;
  var Signature: TBytes;
  SetLength(Key, KeySize);
  SetLength(Signature, SignatureSize);

  const Algorithm = Bytes(Ed25519AlgorithmHex);
  const EmptyName = TTestSupport.DerElement(SequenceTag, nil);
  const KeyInfo   = TTestSupport.DerElement(SequenceTag, Algorithm + BitString(Key));
  const TbsFields = Bytes(VersionHex) + Bytes(SerialHex) + Algorithm + EmptyName + EmptyName + EmptyName + KeyInfo +
                    OptionalFields;
  const Tbs       = TTestSupport.DerElement(SequenceTag, TbsFields);

  Result := TTestSupport.DerElement(SequenceTag, Tbs + Algorithm + BitString(Signature));
end;

function TX509Tests.Parses(const Der: TBytes): Boolean;
begin
  var Certificate: TX509CertificateInfo;
  Result := TX509CertificateInfo.TryParse(Der, Certificate);
end;

procedure TX509Tests.TryParse_CraftedCertificateWithExtension_ReturnsTrue;
begin
  const SingleExtension = Extension(1);
  const Fields          = ExtensionList(SingleExtension);
  const Der             = CraftedCertificate(VersionThreeHex, SerialOneHex, Fields);
  var Certificate: TX509CertificateInfo;

  const Parsed = TX509CertificateInfo.TryParse(Der, Certificate);

  Assert.IsTrue(Parsed);
  Assert.AreEqual(3, Certificate.Version);
  Assert.AreEqual(1, Integer(Length(Certificate.Extensions)));
  Assert.AreEqual('1.2.3.16385', Certificate.Extensions[0].Oid);
end;

procedure TX509Tests.TryParse_ExplicitDefaultVersion_ReturnsFalse;
begin
  const Der = CraftedCertificate(VersionOneHex, SerialOneHex, nil);

  const Parsed = Parses(Der);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TryParse_SerialNumberEncoding_AcceptsMinimalOnly(const SerialHex: string; const Expected: Boolean);
begin
  const Der = CraftedCertificate(VersionThreeHex, SerialHex, nil);

  const Parsed = Parses(Der);

  Assert.AreEqual(Expected, Parsed);
end;

procedure TX509Tests.TryParse_UniqueIdentifiers_NeedVersionTwo(const VersionHex: string;
                                                               const FieldsHex: string;
                                                               const Expected: Boolean);
begin
  const Fields = Bytes(FieldsHex);
  const Der    = CraftedCertificate(VersionHex, SerialOneHex, Fields);

  const Parsed = Parses(Der);

  Assert.AreEqual(Expected, Parsed);
end;

procedure TX509Tests.TryParse_Extensions_NeedVersionThree(const VersionHex: string; const Expected: Boolean);
begin
  const SingleExtension = Extension(1);
  const Fields          = ExtensionList(SingleExtension);
  const Der             = CraftedCertificate(VersionHex, SerialOneHex, Fields);

  const Parsed = Parses(Der);

  Assert.AreEqual(Expected, Parsed);
end;

procedure TX509Tests.TryParse_UniqueIdentifierEncoding_AcceptsDerBitStringOnly(const UniqueIdHex: string;
                                                                               const Expected: Boolean);
begin
  const UniqueId = Bytes(UniqueIdHex);
  const Der      = CraftedCertificate(VersionTwoHex, SerialOneHex, UniqueId);

  const Parsed = Parses(Der);

  Assert.AreEqual(Expected, Parsed);
end;

procedure TX509Tests.TryParse_DuplicateExtension_ReturnsFalse;
begin
  const Extensions = Extension(1) + Extension(2) + Extension(1);
  const Fields     = ExtensionList(Extensions);
  const Der        = CraftedCertificate(VersionThreeHex, SerialOneHex, Fields);

  const Parsed = Parses(Der);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TryParse_EmptyExtensionList_ReturnsFalse;
begin
  const EmptyList = ExtensionList(nil);
  const Der       = CraftedCertificate(VersionThreeHex, SerialOneHex, EmptyList);

  const Parsed = Parses(Der);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TryParse_ManyExtensions_FinishesWithinTimeLimit;
begin
  const ExtensionSize = Length(Extension(0));
  var Extensions: TBytes;
  SetLength(Extensions, ManyExtensions * ExtensionSize);
  for var Number := 0 to ManyExtensions - 1 do
  begin
    const Encoded = Extension(Number);
    Move(Encoded[0], Extensions[Number * ExtensionSize], ExtensionSize);
  end;
  const Fields = ExtensionList(Extensions);
  const Der    = CraftedCertificate(VersionThreeHex, SerialOneHex, Fields);
  var Certificate: TX509CertificateInfo;

  const Watch     = TStopwatch.StartNew;
  const Parsed    = TX509CertificateInfo.TryParse(Der, Certificate);
  const ElapsedMs = Watch.ElapsedMilliseconds;

  Assert.IsTrue(Parsed);
  Assert.AreEqual(ManyExtensions, Integer(Length(Certificate.Extensions)));
  Assert.IsTrue(ElapsedMs < TimeLimitMs, Format('%d extensions took %d ms', [ManyExtensions, ElapsedMs]));
end;

procedure TX509Tests.TryParse_OpenSslCertificate_MatchesOpenSslReport(const FileName: string);
begin
  const Entry = ManifestEntry(FileName);

  const Certificate = Parse(FileName);

  const ExpectedSerial    = Entry.GetValue<string>('serialNumber');
  const ExpectedAlgorithm = Entry.GetValue<string>(AlgorithmName);
  const ExpectedKey       = Entry.GetValue<string>('publicKey');
  const ActualSerial      = TTestSupport.BytesToHex(Certificate.SerialNumber);
  const ActualKey         = TTestSupport.BytesToHex(Certificate.PublicKey.Encoded);
  Assert.AreEqual(3, Certificate.Version);
  Assert.AreEqual(ExpectedSerial, ActualSerial);
  Assert.AreEqual(ExpectedAlgorithm, Certificate.SignatureAlgorithm.Oid);
  Assert.AreEqual(ExpectedAlgorithm, Certificate.TbsSignatureAlgorithm.Oid);
  Assert.AreEqual(ExpectedKey, ActualKey);
  Assert.AreEqual(SequenceTag, Integer(Certificate.Issuer[0]));
  Assert.AreEqual(SequenceTag, Integer(Certificate.Subject[0]));
  Assert.AreEqual(SequenceTag, Integer(Certificate.Validity[0]));
end;

procedure TX509Tests.IsSignedBy_IssuerKey_ReturnsTrue(const FileName: string);
begin
  const Entry       = ManifestEntry(FileName);
  const Certificate = Parse(FileName);
  const IssuerFile  = Entry.GetValue<string>('signedBy');
  const Issuer      = Parse(IssuerFile);

  const Verified = Certificate.IsSignedBy(Issuer.PublicKey);

  Assert.IsTrue(Verified);
end;

procedure TX509Tests.IsSignedBy_OwnKeyOfLeaf_ReturnsFalse;
begin
  const Leaf = Parse(LeafFile);

  const Verified = Leaf.IsSignedBy(Leaf.PublicKey);

  Assert.IsFalse(Verified);
end;

procedure TX509Tests.IsSignedBy_KeyOfOtherAlgorithm_ReturnsFalse(const FileName: string; const OtherFileName: string);
begin
  const Certificate = Parse(FileName);
  const Other       = Parse(OtherFileName);

  const Verified = Certificate.IsSignedBy(Other.PublicKey);

  Assert.IsFalse(Verified);
end;

procedure TX509Tests.IsSignedBy_EcdsaAlgorithmWithParameter_AcceptsNullInBothOnly(const FileName: string;
                                                                                  const Expected: Boolean);
begin
  const Certificate = Parse(FileName);

  const Verified = Certificate.IsSignedBy(Certificate.PublicKey);

  Assert.AreEqual(Expected, Verified);
end;

procedure TX509Tests.TryParse_OneBitFlippedPerByte_NeverVerifiesAndNeverRaises(const FileName: string);
begin
  const Original  = Load(FileName);
  const IssuerKey = Parse(FileName).PublicKey;
  var ParsedCount := 0;

  for var ByteIndex := 0 to High(Original) do
  begin
    const BitIndex = ByteIndex * 8 + (ByteIndex mod 8);
    const Damaged  = TTestSupport.FlipBit(Original, BitIndex);

    var Certificate: TX509CertificateInfo;
    const Parsed = TX509CertificateInfo.TryParse(Damaged, Certificate);
    if Parsed then
    begin
      Inc(ParsedCount);
      const VerifiedByOriginalKey = Certificate.IsSignedBy(IssuerKey);
      const VerifiedByOwnKey      = Certificate.IsSignedBy(Certificate.PublicKey);
      Assert.IsFalse(VerifiedByOriginalKey, Format('byte %d by original key', [ByteIndex]));
      Assert.IsFalse(VerifiedByOwnKey, Format('byte %d by own key', [ByteIndex]));
    end;
  end;

  const Summary     = Format('%s: %d damaged variants, %d still parse and none verifies',
                             [FileName, Length(Original), ParsedCount]);
  const SomeParsed  = (ParsedCount > 0);
  TTestSupport.Log(Summary);
  Assert.IsTrue(SomeParsed);
end;

procedure TX509Tests.TryParse_AnyTruncation_ReturnsFalse(const FileName: string);
begin
  const Original = Load(FileName);
  for var KeptLength := 0 to Length(Original) - 1 do
  begin
    const Truncated = Copy(Original, 0, KeptLength);
    var Certificate: TX509CertificateInfo;

    const Parsed = TX509CertificateInfo.TryParse(Truncated, Certificate);

    Assert.IsFalse(Parsed, Format('length %d', [KeptLength]));
  end;
end;

procedure TX509Tests.TryParse_TrailingByte_ReturnsFalse;
begin
  const Extended = Load(P256File) + TBytes.Create(0);
  var Certificate: TX509CertificateInfo;

  const Parsed = TX509CertificateInfo.TryParse(Extended, Certificate);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TryParse_Empty_ReturnsFalse;
begin
  var Certificate: TX509CertificateInfo;

  const Parsed = TX509CertificateInfo.TryParse(nil, Certificate);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TbsCertificate_OfParsedCertificate_IsFirstElementOfCertificate;
begin
  const Original    = Load(RsaFile);
  const Certificate = Parse(RsaFile);

  const Tbs      = Certificate.TbsCertificate;
  const Expected = Copy(Original, OuterHeaderSize, Length(Tbs));

  const ExpectedHex = TTestSupport.BytesToHex(Expected);
  const ActualHex   = TTestSupport.BytesToHex(Tbs);
  Assert.AreEqual(ExpectedHex, ActualHex);
end;

procedure TX509Tests.TryFindExtension_PresentExtension_ReturnsValue;
begin
  const Certificate = Parse(P256File);
  var Extension: TX509Extension;

  const Found = Certificate.TryFindExtension(SubjectKeyIdOid, Extension);

  Assert.IsTrue(Found);
  Assert.IsFalse(Extension.Critical);
  Assert.AreEqual(KeyIdentifierSize, Integer(Length(Extension.Value)));
end;

procedure TX509Tests.TryFindExtension_CriticalExtension_ReportsCritical;
begin
  const Certificate = Parse(P256File);
  var Extension: TX509Extension;

  const Found = Certificate.TryFindExtension(BasicConstraintsOid, Extension);

  Assert.IsTrue(Found);
  const ValueHex = TTestSupport.BytesToHex(Extension.Value);
  Assert.IsTrue(Extension.Critical);
  Assert.AreEqual('30030101ff', ValueHex);
end;

procedure TX509Tests.TryFindExtension_AbsentExtension_ReturnsFalse;
begin
  const Certificate = Parse(P256File);
  var Extension: TX509Extension;

  const Found = Certificate.TryFindExtension(UnknownOid, Extension);

  Assert.IsFalse(Found);
end;

procedure TX509Tests.PublicKeyInfoTryParse_Garbage_ReturnsFalse;
begin
  const Garbage = TBytes.Create($30, $03, $02, $01, $05);
  var PublicKey: TX509PublicKeyInfo;

  const Parsed = TX509PublicKeyInfo.TryParse(Garbage, PublicKey);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TryGetKey_OtherAlgorithm_ReturnsFalse;
begin
  const P256Key = Parse(P256File).PublicKey;
  const RsaKey  = Parse(RsaFile).PublicKey;
  var EcdsaKey: TEcdsaP256PublicKey;
  var RsaPublicKey: TRsaPublicKey;
  var Ed25519Key: TBytes;

  Assert.IsTrue(P256Key.TryGetEcdsaP256Key(EcdsaKey));
  Assert.IsTrue(RsaKey.TryGetRsaKey(RsaPublicKey));
  Assert.IsFalse(RsaKey.TryGetEcdsaP256Key(EcdsaKey));
  Assert.IsFalse(P256Key.TryGetRsaKey(RsaPublicKey));
  Assert.IsFalse(P256Key.TryGetEd25519Key(Ed25519Key));
end;

procedure TX509Tests.TryGetRsaKey_KeyLimits_AcceptsSupportedKeysOnly(const LowestModulusByte: Byte;
                                                                     const ExponentHex: string;
                                                                     const Expected: Boolean);
begin
  const Der = RsaKeyInfo(LowestModulusByte, ExponentHex);
  var PublicKey: TX509PublicKeyInfo;
  var Key: TRsaPublicKey;

  const Parsed    = TX509PublicKeyInfo.TryParse(Der, PublicKey);
  const Converted = PublicKey.TryGetRsaKey(Key);

  Assert.IsTrue(Parsed);
  Assert.AreEqual(Expected, Converted);
end;

end.
