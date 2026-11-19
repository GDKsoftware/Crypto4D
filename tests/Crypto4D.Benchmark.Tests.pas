unit Crypto4D.Benchmark.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework;

type
  TVerification = reference to function: Boolean;

  [TestFixture]
  [Category('Benchmark')]
  TBenchmarkTests = class
  private
    const
      Repetitions      = 20;
      WycheproofFolder = 'wycheproof/';
      GroupsName       = 'testGroups';
      TestsName        = 'tests';
      MessageName      = 'msg';
      SignatureName    = 'sig';

    function FirstGroup(const Document: TJSONObject): TJSONObject;
    function FirstTest(const Group: TJSONObject): TJSONObject;
    procedure Measure(const Name: string; const Verification: TVerification);
    procedure MeasureRsa(const FileName: string);

  public
    [Test]
    procedure BuildSettings_DebugBuild_HasOverflowAndRangeChecks;

    [Test]
    procedure EcdsaP256_Verify_ReportsTimePerVerification;

    [Test]
    procedure Ed25519_Verify_ReportsTimePerVerification;

    [Test]
    [TestCase('Rsa2048', 'rsa_signature_2048_sha256_test.json')]
    [TestCase('Rsa3072', 'rsa_signature_3072_sha256_test.json')]
    [TestCase('Rsa4096', 'rsa_signature_4096_sha256_test.json')]
    procedure RsaPkcs1Sha256_Verify_ReportsTimePerVerification(const FileName: string);
  end;

implementation

uses
  System.Diagnostics,
  Crypto4D.Ecdsa,
  Crypto4D.Ed25519,
  Crypto4D.Rsa,
  Crypto4D.TestSupport;

procedure TBenchmarkTests.BuildSettings_DebugBuild_HasOverflowAndRangeChecks;
begin
  const OverflowChecks = {$IFOPT Q+}True{$ELSE}False{$ENDIF};
  const RangeChecks    = {$IFOPT R+}True{$ELSE}False{$ENDIF};

  const OverflowText = BoolToStr(OverflowChecks, True);
  const RangeText    = BoolToStr(RangeChecks, True);
  const Settings     = Format('overflow checks: %s, range checks: %s', [OverflowText, RangeText]);
  TTestSupport.Log(Settings);
  {$IFDEF DEBUG}
  Assert.IsTrue(OverflowChecks, 'overflow checks');
  Assert.IsTrue(RangeChecks, 'range checks');
  {$ELSE}
  Assert.Pass;
  {$ENDIF}
end;

function TBenchmarkTests.FirstGroup(const Document: TJSONObject): TJSONObject;
begin
  const Groups = TTestSupport.ArrayOf(Document, GroupsName);
  Result := TTestSupport.ObjectAt(Groups, 0);
end;

function TBenchmarkTests.FirstTest(const Group: TJSONObject): TJSONObject;
begin
  const Tests = TTestSupport.ArrayOf(Group, TestsName);
  Result := TTestSupport.ObjectAt(Tests, 0);
end;

procedure TBenchmarkTests.Measure(const Name: string; const Verification: TVerification);
begin
  var AllVerified := True;
  const Watch = TStopwatch.StartNew;
  for var Repetition := 1 to Repetitions do
  begin
    AllVerified := Verification() and AllVerified;
  end;
  Watch.Stop;

  const Elapsed          = Watch.Elapsed;
  const MillisecondsEach = Elapsed.TotalMilliseconds / Repetitions;
  const Timing           = Format('%s: %.3f ms per verification (%d runs)', [Name, MillisecondsEach, Repetitions],
                                  TFormatSettings.Invariant);
  TTestSupport.Log(Timing);
  Assert.IsTrue(AllVerified, Name);
end;

procedure TBenchmarkTests.EcdsaP256_Verify_ReportsTimePerVerification;
begin
  const Document = TTestSupport.LoadJsonObject(WycheproofFolder + 'ecdsa_secp256r1_sha256_test.json');
  try
    const Group     = FirstGroup(Document);
    const Test      = FirstTest(Group);
    const Point     = TTestSupport.BytesOf(Group, 'publicKey.uncompressed');
    const Key       = TEcdsaP256PublicKey.FromUncompressedPoint(Point);
    const Message   = TTestSupport.BytesOf(Test, MessageName);
    const Signature = TTestSupport.BytesOf(Test, SignatureName);

    Measure('ECDSA P-256 SHA-256',
      function: Boolean
      begin
        Result := TEcdsaP256.VerifyDer(Key, Message, Signature);
      end);
  finally
    Document.Free;
  end;
end;

procedure TBenchmarkTests.Ed25519_Verify_ReportsTimePerVerification;
begin
  const Document = TTestSupport.LoadJsonObject('rfc8032/ed25519.json');
  try
    const Vectors   = TTestSupport.ArrayOf(Document, 'vectors');
    const Vector    = TTestSupport.ObjectAt(Vectors, 2);
    const Key       = TTestSupport.BytesOf(Vector, 'publicKey');
    const Message   = TTestSupport.BytesOf(Vector, 'message');
    const Signature = TTestSupport.BytesOf(Vector, 'signature');

    Measure('Ed25519',
      function: Boolean
      begin
        Result := TEd25519.Verify(Key, Message, Signature);
      end);
  finally
    Document.Free;
  end;
end;

procedure TBenchmarkTests.RsaPkcs1Sha256_Verify_ReportsTimePerVerification(const FileName: string);
begin
  MeasureRsa(FileName);
end;

procedure TBenchmarkTests.MeasureRsa(const FileName: string);
begin
  const Document = TTestSupport.LoadJsonObject(WycheproofFolder + FileName);
  try
    const Group     = FirstGroup(Document);
    const Test      = FirstTest(Group);
    const Modulus   = TTestSupport.BytesOf(Group, 'publicKey.modulus');
    const Exponent  = TTestSupport.BytesOf(Group, 'publicKey.publicExponent');
    const Key       = TRsaPublicKey.Create(Modulus, Exponent);
    const Message   = TTestSupport.BytesOf(Test, MessageName);
    const Signature = TTestSupport.BytesOf(Test, SignatureName);
    const KeySize   = Group.GetValue<Integer>('keySize');
    const Name      = Format('RSA PKCS#1 v1.5 SHA-256, %d bit', [KeySize]);

    Measure(Name,
      function: Boolean
      begin
        Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
      end);
  finally
    Document.Free;
  end;
end;

end.
