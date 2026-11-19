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
      PointName          = 'publicKey.uncompressed';
      ResultName         = 'result';
      TestIdName         = 'tcId';

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
    [TestCase('Rsa8192', 'rsa_signature_8192_sha256_test.json,258')]
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
    for var Index := 0 to High(FMixedOrderAccepted) do
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
      const Point = TTestSupport.BytesOf(Group, PointName);
      const Key   = TEcdsaP256PublicKey.FromUncompressedPoint(Point);
      Result := TEcdsaP256.VerifyDer(Key, Message, Signature);
    end);
end;

procedure TWycheproofTests.EcdsaP256Sha256_RawSignatures_MatchExpectedResults;
begin
  CheckFile('ecdsa_secp256r1_sha256_p1363_test.json', 262,
    function(const Group: TJSONObject; const Message, Signature: TBytes): Boolean
    begin
      const Point = TTestSupport.BytesOf(Group, PointName);
      const Key   = TEcdsaP256PublicKey.FromUncompressedPoint(Point);
      Result := TEcdsaP256.VerifyRaw(Key, Message, Signature);
    end);
end;

procedure TWycheproofTests.Ed25519_Signatures_MatchExpectedResults;
begin
  CheckFile('ed25519_test.json', 210,
    function(const Group: TJSONObject; const Message, Signature: TBytes): Boolean
    begin
      const Key = TTestSupport.BytesOf(Group, 'publicKey.pk');
      Result := TEd25519.Verify(Key, Message, Signature);
    end);
end;

procedure TWycheproofTests.RsaPkcs1Sha256_Signatures_MatchExpectedResults(const FileName: string; const ExpectedTotal: Integer);
begin
  CheckFile(FileName, ExpectedTotal, VerifyRsa);
end;

function TWycheproofTests.VerifyRsa(const Group: TJSONObject; const Message, Signature: TBytes): Boolean;
begin
  const Modulus  = TTestSupport.BytesOf(Group, 'publicKey.modulus');
  const Exponent = TTestSupport.BytesOf(Group, 'publicKey.publicExponent');
  const Key      = TRsaPublicKey.Create(Modulus, Exponent);

  Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
end;

procedure TWycheproofTests.CheckFile(const FileName: string; const ExpectedTotal: Integer; const Verifier: TWycheproofVerifier);
begin
  const Tally = RunFile(FileName, Verifier);

  const Summary    = Format('%s: %d vectors (%d valid, %d invalid, acceptable: %d accepted and %d rejected), %d mismatches',
                            [FileName, Tally.Total, Tally.Valid, Tally.Invalid,
                             Tally.AcceptableAccepted, Tally.AcceptableRejected, Length(Tally.Mismatches)]);
  const Mismatches = string.Join('; ', Tally.Mismatches);
  TTestSupport.Log(Summary);
  Assert.AreEqual(ExpectedTotal, Tally.Total, 'number of vectors');
  Assert.AreEqual('', Mismatches);
end;

function TWycheproofTests.RunFile(const FileName: string; const Verifier: TWycheproofVerifier): TWycheproofTally;
begin
  Result := Default(TWycheproofTally);

  const Document = TTestSupport.LoadJsonObject(Folder + FileName);
  try
    const Groups = TTestSupport.ArrayOf(Document, 'testGroups');
    for var Item in Groups do
    begin
      const Group = Item as TJSONObject;
      RunGroup(Group, Verifier, Result);
    end;
  finally
    Document.Free;
  end;
end;

procedure TWycheproofTests.RunGroup(const Group: TJSONObject; const Verifier: TWycheproofVerifier; var Tally: TWycheproofTally);
begin
  const Tests = TTestSupport.ArrayOf(Group, 'tests');
  for var Item in Tests do
  begin
    const Test      = Item as TJSONObject;
    const Message   = TTestSupport.BytesOf(Test, 'msg');
    const Signature = TTestSupport.BytesOf(Test, 'sig');
    const Verified  = Verifier(Group, Message, Signature);

    CountTest(Test, Verified, Tally);
  end;
end;

procedure TWycheproofTests.CountTest(const Test: TJSONObject; const Verified: Boolean; var Tally: TWycheproofTally);
begin
  const Outcome   = Test.GetValue<string>(ResultName);
  const IsValid   = (Outcome = ResultValid);
  const IsInvalid = (Outcome = ResultInvalid);
  Inc(Tally.Total);
  if IsValid then
    Inc(Tally.Valid)
  else if IsInvalid then
    Inc(Tally.Invalid)
  else if Verified then
    Inc(Tally.AcceptableAccepted)
  else
    Inc(Tally.AcceptableRejected);

  const Expected     = IsExpectedToVerify(Test);
  const IsUnexpected = (Verified <> Expected);
  if IsUnexpected then
  begin
    const TestId       = Test.GetValue<Integer>(TestIdName);
    const Comment      = Test.GetValue<string>('comment');
    const VerifiedText = BoolToStr(Verified, True);
    const Mismatch     = Format('tcId %d (%s, "%s") verified=%s', [TestId, Outcome, Comment, VerifiedText]);
    Tally.Mismatches := Tally.Mismatches + [Mismatch];
  end;
end;

function TWycheproofTests.IsExpectedToVerify(const Test: TJSONObject): Boolean;
begin
  const Outcome      = Test.GetValue<string>(ResultName);
  const IsValid      = (Outcome = ResultValid);
  const IsInvalid    = (Outcome = ResultInvalid);
  const IsAcceptable = (Outcome = ResultAcceptable);
  if IsValid then
    Exit(True);
  if IsInvalid then
    Exit(False);
  if not IsAcceptable then
    raise ETestSupportError.CreateFmt('Unknown Wycheproof result "%s"', [Outcome]);

  Result := AcceptableIsExpectedToVerify(Test);
end;

function TWycheproofTests.AcceptableIsExpectedToVerify(const Test: TJSONObject): Boolean;
begin
  if HasFlag(Test, FlagMissingNull) then
    Exit(False);
  if HasFlag(Test, FlagSmallOrderKey) then
    Exit(False);

  const TestId = Test.GetValue<Integer>(TestIdName);
  if not HasFlag(Test, FlagMixedOrderKey) then
    raise ETestSupportError.CreateFmt('No policy for acceptable Wycheproof vector %d', [TestId]);

  for var AcceptedId in FMixedOrderAccepted do
  begin
    const IsAccepted = (AcceptedId = TestId);
    if IsAccepted then
      Exit(True);
  end;

  Result := False;
end;

function TWycheproofTests.HasFlag(const Test: TJSONObject; const Flag: string): Boolean;
begin
  const Flags = TTestSupport.ArrayOf(Test, 'flags');
  for var Item in Flags do
  begin
    const IsWanted = (Item.Value = Flag);
    if IsWanted then
      Exit(True);
  end;

  Result := False;
end;

end.
