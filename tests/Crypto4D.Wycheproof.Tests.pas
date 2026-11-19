unit Crypto4D.Wycheproof.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework;

type
  TWycheproofVerifier = reference to function(const Group: TJSONObject; const Message, Signature: TBytes): Boolean;

  TWycheproofTally = record
    Total: Integer;
    Valid: Integer;
    Invalid: Integer;
    AcceptableAccepted: Integer;
    AcceptableRejected: Integer;
    Mismatches: TArray<string>;
  end;

  [TestFixture]
  TWycheproofTests = class
  private
    const
      Folder             = 'wycheproof/';
      ResultValid        = 'valid';
      ResultInvalid      = 'invalid';
      ResultAcceptable   = 'acceptable';
      FlagMissingNull    = 'MissingNull';
      FlagSmallOrderKey  = 'SmallOrderPublicKey';
      FlagMixedOrderKey  = 'MixedOrderPublicKey';
      MixedOrderFile     = 'wycheproof/ed25519_mixed_order_expected.json';
      PublicKeyName      = 'publicKey';

    var
      FMixedOrderAccepted: TArray<Integer>;

    procedure LoadMixedOrderExpectations;
    function IsExpectedToVerify(const Test: TJSONObject): Boolean;
    function AcceptableIsExpectedToVerify(const Test: TJSONObject): Boolean;
    function HasFlag(const Test: TJSONObject; const Flag: string): Boolean;
    function RunFile(const FileName: string; const Verifier: TWycheproofVerifier): TWycheproofTally;
    procedure RunGroup(const Group: TJSONObject; const Verifier: TWycheproofVerifier; var Tally: TWycheproofTally);
    procedure CountTest(const Test: TJSONObject; const Verified: Boolean; var Tally: TWycheproofTally);
    procedure CheckFile(const FileName: string; const ExpectedTotal: Integer; const Verifier: TWycheproofVerifier);
    function VerifyRsa(const Group: TJSONObject; const Message, Signature: TBytes): Boolean;

  public
    [SetupFixture]
    procedure SetupFixture;

    [Test]
    procedure EcdsaP256Sha256_DerSignatures_MatchExpectedResults;

    [Test]
    procedure EcdsaP256Sha256_RawSignatures_MatchExpectedResults;

    [Test]
    procedure Ed25519_Signatures_MatchExpectedResults;

    [Test]
    [TestCase('Rsa2048', 'rsa_signature_2048_sha256_test.json,259')]
    [TestCase('Rsa3072', 'rsa_signature_3072_sha256_test.json,259')]
    [TestCase('Rsa4096', 'rsa_signature_4096_sha256_test.json,258')]
    procedure RsaPkcs1Sha256_Signatures_MatchExpectedResults(const FileName: string; const ExpectedTotal: Integer);
  end;

implementation

uses
  Crypto4D.Ecdsa,
  Crypto4D.Ed25519,
  Crypto4D.Rsa,
  Crypto4D.TestSupport;

procedure TWycheproofTests.SetupFixture;
begin
  LoadMixedOrderExpectations;
end;

procedure TWycheproofTests.LoadMixedOrderExpectations;
begin
  const Document = TTestSupport.LoadJsonObject(MixedOrderFile);
  try
    const Accepted = TTestSupport.ArrayOf(Document, 'verifiesWithCofactorlessEquation');
    SetLength(FMixedOrderAccepted, Accepted.Count);
    for var Index := 0 to Accepted.Count - 1 do
    begin
      FMixedOrderAccepted[Index] := TTestSupport.IntegerAt(Accepted, Index);
    end;
  finally
    Document.Free;
  end;
end;

procedure TWycheproofTests.EcdsaP256Sha256_DerSignatures_MatchExpectedResults;
begin
  CheckFile('ecdsa_secp256r1_sha256_test.json', 484,
    function(const Group: TJSONObject; const Message, Signature: TBytes): Boolean
    begin
      const Point = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.uncompressed'));
      const Key   = TEcdsaP256PublicKey.FromUncompressedPoint(Point);
      Result := TEcdsaP256.VerifyDer(Key, Message, Signature);
    end);
end;

procedure TWycheproofTests.EcdsaP256Sha256_RawSignatures_MatchExpectedResults;
begin
  CheckFile('ecdsa_secp256r1_sha256_p1363_test.json', 262,
    function(const Group: TJSONObject; const Message, Signature: TBytes): Boolean
    begin
      const Point = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.uncompressed'));
      const Key   = TEcdsaP256PublicKey.FromUncompressedPoint(Point);
      Result := TEcdsaP256.VerifyRaw(Key, Message, Signature);
    end);
end;

procedure TWycheproofTests.Ed25519_Signatures_MatchExpectedResults;
begin
  CheckFile('ed25519_test.json', 210,
    function(const Group: TJSONObject; const Message, Signature: TBytes): Boolean
    begin
      const Key = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.pk'));
      Result := TEd25519.Verify(Key, Message, Signature);
    end);
end;

procedure TWycheproofTests.RsaPkcs1Sha256_Signatures_MatchExpectedResults(const FileName: string; const ExpectedTotal: Integer);
begin
  CheckFile(FileName, ExpectedTotal, VerifyRsa);
end;

function TWycheproofTests.VerifyRsa(const Group: TJSONObject; const Message, Signature: TBytes): Boolean;
begin
  const Modulus  = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.modulus'));
  const Exponent = TTestSupport.HexToBytes(Group.GetValue<string>('publicKey.publicExponent'));
  const Key      = TRsaPublicKey.Create(Modulus, Exponent);

  Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
end;

procedure TWycheproofTests.CheckFile(const FileName: string; const ExpectedTotal: Integer; const Verifier: TWycheproofVerifier);
begin
  const Tally = RunFile(FileName, Verifier);

  TTestSupport.Log(Format('%s: %d vectors (%d valid, %d invalid, acceptable: %d accepted and %d rejected), %d mismatches',
                          [FileName, Tally.Total, Tally.Valid, Tally.Invalid,
                           Tally.AcceptableAccepted, Tally.AcceptableRejected, Length(Tally.Mismatches)]));
  Assert.AreEqual(ExpectedTotal, Tally.Total, 'number of vectors');
  Assert.AreEqual('', string.Join('; ', Tally.Mismatches));
end;

function TWycheproofTests.RunFile(const FileName: string; const Verifier: TWycheproofVerifier): TWycheproofTally;
begin
  Result := Default(TWycheproofTally);

  const Document = TTestSupport.LoadJsonObject(Folder + FileName);
  try
    const Groups = TTestSupport.ArrayOf(Document, 'testGroups');
    for var Index := 0 to Groups.Count - 1 do
    begin
      const Group = TTestSupport.ObjectAt(Groups, Index);
      RunGroup(Group, Verifier, Result);
    end;
  finally
    Document.Free;
  end;
end;

procedure TWycheproofTests.RunGroup(const Group: TJSONObject; const Verifier: TWycheproofVerifier; var Tally: TWycheproofTally);
begin
  const Tests = TTestSupport.ArrayOf(Group, 'tests');
  for var Index := 0 to Tests.Count - 1 do
  begin
    const Test      = TTestSupport.ObjectAt(Tests, Index);
    const Message   = TTestSupport.HexToBytes(Test.GetValue<string>('msg'));
    const Signature = TTestSupport.HexToBytes(Test.GetValue<string>('sig'));
    const Verified  = Verifier(Group, Message, Signature);

    CountTest(Test, Verified, Tally);
  end;
end;

procedure TWycheproofTests.CountTest(const Test: TJSONObject; const Verified: Boolean; var Tally: TWycheproofTally);
begin
  const Outcome = Test.GetValue<string>('result');
  Inc(Tally.Total);
  if Outcome = ResultValid then
    Inc(Tally.Valid)
  else if Outcome = ResultInvalid then
    Inc(Tally.Invalid)
  else if Verified then
    Inc(Tally.AcceptableAccepted)
  else
    Inc(Tally.AcceptableRejected);

  const Expected = IsExpectedToVerify(Test);
  if Verified <> Expected then
  begin
    const Mismatch = Format('tcId %d (%s, "%s") verified=%s',
                            [Test.GetValue<Integer>('tcId'), Outcome, Test.GetValue<string>('comment'),
                             BoolToStr(Verified, True)]);
    Tally.Mismatches := Tally.Mismatches + [Mismatch];
  end;
end;

function TWycheproofTests.IsExpectedToVerify(const Test: TJSONObject): Boolean;
begin
  const Outcome = Test.GetValue<string>('result');
  if Outcome = ResultValid then
    Exit(True);
  if Outcome = ResultInvalid then
    Exit(False);
  if Outcome = ResultAcceptable then
    Exit(AcceptableIsExpectedToVerify(Test));

  raise ETestSupportError.CreateFmt('Unknown Wycheproof result "%s"', [Outcome]);
end;

function TWycheproofTests.AcceptableIsExpectedToVerify(const Test: TJSONObject): Boolean;
begin
  if HasFlag(Test, FlagMissingNull) then
    Exit(False);
  if HasFlag(Test, FlagSmallOrderKey) then
    Exit(False);

  if HasFlag(Test, FlagMixedOrderKey) then
  begin
    const TestId = Test.GetValue<Integer>('tcId');
    for var AcceptedId in FMixedOrderAccepted do
    begin
      if AcceptedId = TestId then
        Exit(True);
    end;
    Exit(False);
  end;

  raise ETestSupportError.CreateFmt('No policy for acceptable Wycheproof vector %d', [Test.GetValue<Integer>('tcId')]);
end;

function TWycheproofTests.HasFlag(const Test: TJSONObject; const Flag: string): Boolean;
begin
  const Flags = TTestSupport.ArrayOf(Test, 'flags');
  for var Index := 0 to Flags.Count - 1 do
  begin
    if TTestSupport.StringAt(Flags, Index) = Flag then
      Exit(True);
  end;

  Result := False;
end;

end.
