unit Crypto4D.OpenSsl.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework,
  Crypto4D.X509;

type
  TCrossCheckTally = record
    Total: Integer;
    ExpectedToVerify: Integer;
    Mismatches: TArray<string>;
  end;

  [TestFixture]
  TOpenSslCrossCheckTests = class
  private
    const
      VectorFileName  = 'openssl/crosscheck.json';
      AlgorithmName   = 'algorithm';
      FamilyEcdsa     = 'ES256';
      FamilyRsa       = 'RS256';
      FamilyEdDsa     = 'EdDSA';
      MinimumCases    = 2000;

    var
      FDocument: TJSONObject;
      FKeys: TJSONArray;
      FCases: TJSONArray;

    function PublicKeyOf(const TestCase: TJSONObject): TX509PublicKeyInfo;
    function Verifies(const TestCase: TJSONObject): Boolean;
    function VerifiesEcdsa(const PublicKey: TX509PublicKeyInfo; const TestCase: TJSONObject; const Message, Signature: TBytes): Boolean;
    function VerifiesRsa(const PublicKey: TX509PublicKeyInfo; const Message, Signature: TBytes): Boolean;
    function VerifiesEdDsa(const PublicKey: TX509PublicKeyInfo; const Message, Signature: TBytes): Boolean;
    function RunFamily(const Family: string): TCrossCheckTally;

  public
    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    [Test]
    procedure VectorFile_HoldsEnoughCases;

    [Test]
    [TestCase('EcdsaP256', 'ES256')]
    [TestCase('RsaPkcs1', 'RS256')]
    [TestCase('Ed25519', 'EdDSA')]
    procedure Verify_OpenSslCases_AgreeWithOpenSsl(const Family: string);
  end;

implementation

uses
  Crypto4D.Ecdsa,
  Crypto4D.Ed25519,
  Crypto4D.Rsa,
  Crypto4D.TestSupport;

procedure TOpenSslCrossCheckTests.SetupFixture;
begin
  FDocument := TTestSupport.LoadJsonObject(VectorFileName);
  FKeys     := TTestSupport.ArrayOf(FDocument, 'keys');
  FCases    := TTestSupport.ArrayOf(FDocument, 'cases');
end;

procedure TOpenSslCrossCheckTests.TearDownFixture;
begin
  FDocument.Free;
end;

procedure TOpenSslCrossCheckTests.VectorFile_HoldsEnoughCases;
begin
  const HasEnoughCases = (FCases.Count >= MinimumCases);

  Assert.IsTrue(HasEnoughCases, Format('%d cases', [FCases.Count]));
end;

procedure TOpenSslCrossCheckTests.Verify_OpenSslCases_AgreeWithOpenSsl(const Family: string);
begin
  const Tally = RunFamily(Family);

  TTestSupport.Log(Format('%s: %d OpenSSL cases (%d verify, %d do not), %d mismatches',
                          [Family, Tally.Total, Tally.ExpectedToVerify,
                           Tally.Total - Tally.ExpectedToVerify, Length(Tally.Mismatches)]));
  Assert.IsTrue(Tally.Total > 0, 'no cases for this algorithm');
  Assert.AreEqual('', string.Join('; ', Tally.Mismatches));
end;

function TOpenSslCrossCheckTests.RunFamily(const Family: string): TCrossCheckTally;
begin
  Result := Default(TCrossCheckTally);

  for var Index := 0 to FCases.Count - 1 do
  begin
    const TestCase     = TTestSupport.ObjectAt(FCases, Index);
    const Algorithm    = TestCase.GetValue<string>(AlgorithmName);
    const IsThisFamily = Algorithm.StartsWith(Family);
    if not IsThisFamily then
      Continue;

    const Expected = TestCase.GetValue<Boolean>('expected');
    const Actual   = Verifies(TestCase);
    Inc(Result.Total);
    if Expected then
      Inc(Result.ExpectedToVerify);

    if Actual <> Expected then
    begin
      const Mismatch = Format('case %d (%s, %s) verified=%s',
                              [Index, Algorithm, TestCase.GetValue<string>('mutation'), BoolToStr(Actual, True)]);
      Result.Mismatches := Result.Mismatches + [Mismatch];
    end;
  end;
end;

function TOpenSslCrossCheckTests.PublicKeyOf(const TestCase: TJSONObject): TX509PublicKeyInfo;
begin
  var KeyHex: string;
  if not TestCase.TryGetValue<string>('damagedKey', KeyHex) then
  begin
    const Key = TTestSupport.ObjectAt(FKeys, TestCase.GetValue<Integer>('key'));
    KeyHex := Key.GetValue<string>('publicKey');
  end;

  const KeyDer = TTestSupport.HexToBytes(KeyHex);
  const Parsed = TX509PublicKeyInfo.TryParse(KeyDer, Result);
  Assert.IsTrue(Parsed, 'public key does not parse');
end;

function TOpenSslCrossCheckTests.Verifies(const TestCase: TJSONObject): Boolean;
begin
  const PublicKey = PublicKeyOf(TestCase);
  const Message   = TTestSupport.HexToBytes(TestCase.GetValue<string>('message'));
  const Signature = TTestSupport.HexToBytes(TestCase.GetValue<string>('signature'));
  const Algorithm = TestCase.GetValue<string>(AlgorithmName);

  if Algorithm.StartsWith(FamilyEcdsa) then
    Exit(VerifiesEcdsa(PublicKey, TestCase, Message, Signature));
  if Algorithm.StartsWith(FamilyRsa) then
    Exit(VerifiesRsa(PublicKey, Message, Signature));
  if Algorithm.StartsWith(FamilyEdDsa) then
    Exit(VerifiesEdDsa(PublicKey, Message, Signature));

  raise ETestSupportError.CreateFmt('Unknown algorithm "%s"', [Algorithm]);
end;

function TOpenSslCrossCheckTests.VerifiesEcdsa(const PublicKey: TX509PublicKeyInfo;
                                               const TestCase: TJSONObject;
                                               const Message, Signature: TBytes): Boolean;
begin
  var Key: TEcdsaP256PublicKey;
  if not PublicKey.TryGetEcdsaP256Key(Key) then
    Exit(False);

  Result := TEcdsaP256.VerifyDer(Key, Message, Signature);

  var RawHex: string;
  if TestCase.TryGetValue<string>('rawSignature', RawHex) then
  begin
    const RawSignature = TTestSupport.HexToBytes(RawHex);
    const RawVerifies  = TEcdsaP256.VerifyRaw(Key, Message, RawSignature);
    Assert.AreEqual(Result, RawVerifies, 'DER and raw signature disagree');
  end;
end;

function TOpenSslCrossCheckTests.VerifiesRsa(const PublicKey: TX509PublicKeyInfo; const Message, Signature: TBytes): Boolean;
begin
  var Key: TRsaPublicKey;
  if not PublicKey.TryGetRsaKey(Key) then
    Exit(False);

  Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
end;

function TOpenSslCrossCheckTests.VerifiesEdDsa(const PublicKey: TX509PublicKeyInfo; const Message, Signature: TBytes): Boolean;
begin
  var Key: TBytes;
  if not PublicKey.TryGetEd25519Key(Key) then
    Exit(False);

  Result := TEd25519.Verify(Key, Message, Signature);
end;

end.
