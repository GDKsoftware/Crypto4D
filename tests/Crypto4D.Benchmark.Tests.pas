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
      Repetitions = 20;

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

  TTestSupport.Log(Format('overflow checks: %s, range checks: %s',
                          [BoolToStr(OverflowChecks, True), BoolToStr(RangeChecks, True)]));
  {$IFDEF DEBUG}
  Assert.IsTrue(OverflowChecks, 'overflow checks');
  Assert.IsTrue(RangeChecks, 'range checks');
  {$ELSE}
  Assert.Pass;
  {$ENDIF}
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

  const MillisecondsEach = Watch.Elapsed.TotalMilliseconds / Repetitions;
  TTestSupport.Log(Format('%s: %.3f ms per verification (%d runs)', [Name, MillisecondsEach, Repetitions],
                          TFormatSettings.Invariant));
  Assert.IsTrue(AllVerified, Name);
end;

procedure TBenchmarkTests.EcdsaP256_Verify_ReportsTimePerVerification;
begin
  const Document = TTestSupport.LoadJsonObject('wycheproof/ecdsa_secp256r1_sha256_test.json');
  try
    const Group     = TTestSupport.ObjectAt(TTestSupport.ArrayOf(Document, 'testGroups'), 0);
    const Test      = TTestSupport.ObjectAt(TTestSupport.ArrayOf(Group, 'tests'), 0);
    const Point     = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.uncompressed'));
    const Key       = TEcdsaP256PublicKey.FromUncompressedPoint(Point);
    const Message   = TTestSupport.HexToBytes(Test.GetValue<string>('msg'));
    const Signature = TTestSupport.HexToBytes(Test.GetValue<string>('sig'));

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
    const Vector    = TTestSupport.ObjectAt(TTestSupport.ArrayOf(Document, 'vectors'), 2);
    const Key       = TTestSupport.HexToBytes(Vector.GetValue<string>('publicKey'));
    const Message   = TTestSupport.HexToBytes(Vector.GetValue<string>('message'));
    const Signature = TTestSupport.HexToBytes(Vector.GetValue<string>('signature'));

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
  const Document = TTestSupport.LoadJsonObject('wycheproof/' + FileName);
  try
    const Group     = TTestSupport.ObjectAt(TTestSupport.ArrayOf(Document, 'testGroups'), 0);
    const Test      = TTestSupport.ObjectAt(TTestSupport.ArrayOf(Group, 'tests'), 0);
    const Modulus   = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.modulus'));
    const Exponent  = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.publicExponent'));
    const Key       = TRsaPublicKey.Create(Modulus, Exponent);
    const Message   = TTestSupport.HexToBytes(Test.GetValue<string>('msg'));
    const Signature = TTestSupport.HexToBytes(Test.GetValue<string>('sig'));

    Measure(Format('RSA PKCS#1 v1.5 SHA-256, %d bit', [Group.GetValue<Integer>('keySize')]),
      function: Boolean
      begin
        Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
      end);
  finally
    Document.Free;
  end;
end;

end.
