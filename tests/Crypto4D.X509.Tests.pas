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

    var
      FManifest: TJSONObject;

    function Load(const FileName: string): TBytes;
    function Parse(const FileName: string): TX509Certificate;
    function ManifestEntry(const FileName: string): TJSONObject;

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
  end;

implementation

uses
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

function TX509Tests.Parse(const FileName: string): TX509Certificate;
begin
  const Parsed = TX509Certificate.TryParse(Load(FileName), Result);
  Assert.IsTrue(Parsed, FileName);
end;

function TX509Tests.ManifestEntry(const FileName: string): TJSONObject;
begin
  const Certificates = TTestSupport.ArrayOf(FManifest, 'certificates');
  for var Index := 0 to Certificates.Count - 1 do
  begin
    const Entry = TTestSupport.ObjectAt(Certificates, Index);
    if Entry.GetValue<string>('file') = FileName then
      Exit(Entry);
  end;

  raise ETestSupportError.CreateFmt('Certificate "%s" is not in the manifest', [FileName]);
end;

procedure TX509Tests.TryParse_OpenSslCertificate_MatchesOpenSslReport(const FileName: string);
begin
  const Entry = ManifestEntry(FileName);

  const Certificate = Parse(FileName);

  Assert.AreEqual(3, Certificate.Version);
  Assert.AreEqual(Entry.GetValue<string>('serialNumber'), TTestSupport.BytesToHex(Certificate.SerialNumber));
  Assert.AreEqual(Entry.GetValue<string>('signatureAlgorithm'), Certificate.SignatureAlgorithm.Oid);
  Assert.AreEqual(Entry.GetValue<string>('signatureAlgorithm'), Certificate.TbsSignatureAlgorithm.Oid);
  Assert.AreEqual(Entry.GetValue<string>('publicKey'), TTestSupport.BytesToHex(Certificate.PublicKey.Encoded));
  Assert.AreEqual(SequenceTag, Integer(Certificate.Issuer[0]));
  Assert.AreEqual(SequenceTag, Integer(Certificate.Subject[0]));
  Assert.AreEqual(SequenceTag, Integer(Certificate.Validity[0]));
end;

procedure TX509Tests.IsSignedBy_IssuerKey_ReturnsTrue(const FileName: string);
begin
  const Entry       = ManifestEntry(FileName);
  const Certificate = Parse(FileName);
  const Issuer      = Parse(Entry.GetValue<string>('signedBy'));

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

procedure TX509Tests.TryParse_OneBitFlippedPerByte_NeverVerifiesAndNeverRaises(const FileName: string);
begin
  const Original  = Load(FileName);
  const IssuerKey = Parse(FileName).PublicKey;
  var ParsedCount := 0;

  for var ByteIndex := 0 to High(Original) do
  begin
    const BitIndex = ByteIndex * 8 + (ByteIndex mod 8);
    const Damaged  = TTestSupport.FlipBit(Original, BitIndex);

    var Certificate: TX509Certificate;
    const Parsed = TX509Certificate.TryParse(Damaged, Certificate);
    if Parsed then
    begin
      Inc(ParsedCount);
      Assert.IsFalse(Certificate.IsSignedBy(IssuerKey), Format('byte %d by original key', [ByteIndex]));
      Assert.IsFalse(Certificate.IsSignedBy(Certificate.PublicKey), Format('byte %d by own key', [ByteIndex]));
    end;
  end;

  TTestSupport.Log(Format('%s: %d damaged variants, %d still parse and none verifies',
                          [FileName, Length(Original), ParsedCount]));
  Assert.IsTrue(ParsedCount > 0);
end;

procedure TX509Tests.TryParse_AnyTruncation_ReturnsFalse(const FileName: string);
begin
  const Original = Load(FileName);
  for var KeptLength := 0 to Length(Original) - 1 do
  begin
    const Truncated = Copy(Original, 0, KeptLength);
    var Certificate: TX509Certificate;

    const Parsed = TX509Certificate.TryParse(Truncated, Certificate);

    Assert.IsFalse(Parsed, Format('length %d', [KeptLength]));
  end;
end;

procedure TX509Tests.TryParse_TrailingByte_ReturnsFalse;
begin
  const Extended = Load(P256File) + TBytes.Create(0);
  var Certificate: TX509Certificate;

  const Parsed = TX509Certificate.TryParse(Extended, Certificate);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TryParse_Empty_ReturnsFalse;
begin
  var Certificate: TX509Certificate;

  const Parsed = TX509Certificate.TryParse(nil, Certificate);

  Assert.IsFalse(Parsed);
end;

procedure TX509Tests.TbsCertificate_OfParsedCertificate_IsFirstElementOfCertificate;
const
  OuterHeaderSize = 4;
begin
  const Original    = Load(RsaFile);
  const Certificate = Parse(RsaFile);

  const Tbs      = Certificate.TbsCertificate;
  const Expected = Copy(Original, OuterHeaderSize, Length(Tbs));

  Assert.AreEqual(TTestSupport.BytesToHex(Expected), TTestSupport.BytesToHex(Tbs));
end;

procedure TX509Tests.TryFindExtension_PresentExtension_ReturnsValue;
const
  KeyIdentifierSize = 22;
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
  Assert.IsTrue(Extension.Critical);
  Assert.AreEqual('30030101ff', TTestSupport.BytesToHex(Extension.Value));
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
  var PublicKey: TX509PublicKeyInfo;

  const Parsed = TX509PublicKeyInfo.TryParse(TBytes.Create($30, $03, $02, $01, $05), PublicKey);

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

end.
