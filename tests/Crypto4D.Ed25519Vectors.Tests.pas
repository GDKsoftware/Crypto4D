unit Crypto4D.Ed25519Vectors.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework,
  Crypto4D.TestSupport;

type
  [TestFixture]
  TEd25519VectorTests = class
  private
    const
      CctvFile        = 'cctv/ed25519vectors.json';
      CctvTotal       = 914;
      CctvAccepted    = 86;
      SpeccheckFile   = 'ed25519-speccheck/cases.json';
      SpeccheckTotal  = 12;
      SignInputFile   = 'ed25519-cr-yp-to/sign_input.json';
      SignInputTotal  = 1024;
      MessageName     = 'message';
      SignatureName   = 'signature';
      BitsPerByte     = 8;
      RejectedCctvFlags: array[0..3] of string = ('low_order_A', 'non_canonical_A', 'non_canonical_R', 'low_order_residue');

    function CctvVectorIsExpectedToVerify(const Vector: TJSONObject): Boolean;
    function IsRejectedCctvFlag(const Flag: string): Boolean;
    function VerifyCctvVector(const Vector: TJSONObject): Boolean;
    function TallySignInput(const DamagesSignature: Boolean): TVerificationTally;

  public
    [Test]
    procedure Verify_CctvVectors_FollowFlagPolicy;

    [Test]
    [TestCase('Case00_SmallOrderKeyAndSmallOrderR', '0,False')]
    [TestCase('Case01_SmallOrderKey', '1,False')]
    [TestCase('Case02_MixedOrderKeyAndSmallOrderR', '2,True')]
    [TestCase('Case03_MixedOrderKeyAndMixedOrderR', '3,True')]
    [TestCase('Case04_HoldsOnlyWithCofactor', '4,False')]
    [TestCase('Case05_HoldsOnlyWithCofactor', '5,False')]
    [TestCase('Case06_SAboveGroupOrder', '6,False')]
    [TestCase('Case07_SFarAboveGroupOrder', '7,False')]
    [TestCase('Case08_NonCanonicalR', '8,False')]
    [TestCase('Case09_NonCanonicalR', '9,False')]
    [TestCase('Case10_NonCanonicalSmallOrderKey', '10,False')]
    [TestCase('Case11_NonCanonicalSmallOrderKey', '11,False')]
    procedure Verify_SpeccheckCase_ReturnsExpected(const CaseIndex: Integer; const Expected: Boolean);

    [Test]
    procedure Verify_SignInputVectors_AllVerify;

    [Test]
    procedure Verify_SignInputVectorsWithFlippedSignatureBit_NeverVerify;
  end;

implementation

uses
  Crypto4D.Ed25519;

procedure TEd25519VectorTests.Verify_CctvVectors_FollowFlagPolicy;
begin
  const Vectors = TTestSupport.LoadJsonArray(CctvFile);
  try
    var Tally := Default(TVerificationTally);
    for var Item in Vectors do
    begin
      const Vector   = Item as TJSONObject;
      const Number   = Vector.GetValue<string>('number');
      const Expected = CctvVectorIsExpectedToVerify(Vector);
      const Verified = VerifyCctvVector(Vector);

      Tally.Add(Number, Expected, Verified);
    end;

    const Summary = Tally.Summary(CctvFile);
    TTestSupport.Log(Summary);
    Assert.AreEqual(CctvTotal, Tally.Total, Summary);
    Assert.AreEqual('', Tally.MismatchList);
    Assert.AreEqual(CctvAccepted, Tally.Verified, Summary);
  finally
    Vectors.Free;
  end;
end;

function TEd25519VectorTests.CctvVectorIsExpectedToVerify(const Vector: TJSONObject): Boolean;
begin
  const Flags    = Vector.FindValue('flags');
  const HasFlags = (Flags is TJSONArray);
  if not HasFlags then
    Exit(True);

  for var Flag in TJSONArray(Flags) do
  begin
    if IsRejectedCctvFlag(Flag.Value) then
      Exit(False);
  end;

  Result := True;
end;

function TEd25519VectorTests.IsRejectedCctvFlag(const Flag: string): Boolean;
begin
  for var Rejected in RejectedCctvFlags do
  begin
    const IsRejected = (Flag = Rejected);
    if IsRejected then
      Exit(True);
  end;

  Result := False;
end;

function TEd25519VectorTests.VerifyCctvVector(const Vector: TJSONObject): Boolean;
begin
  const Key       = TTestSupport.BytesOf(Vector, 'key');
  const Signature = TTestSupport.BytesOf(Vector, 'sig');
  const Text      = Vector.GetValue<string>('msg');
  const Message   = TEncoding.UTF8.GetBytes(Text);

  Result := TEd25519.Verify(Key, Message, Signature);
end;

procedure TEd25519VectorTests.Verify_SpeccheckCase_ReturnsExpected(const CaseIndex: Integer; const Expected: Boolean);
begin
  const Cases = TTestSupport.LoadJsonArray(SpeccheckFile);
  try
    const Entry     = TTestSupport.ObjectAt(Cases, CaseIndex);
    const Key       = TTestSupport.BytesOf(Entry, 'pub_key');
    const Message   = TTestSupport.BytesOf(Entry, MessageName);
    const Signature = TTestSupport.BytesOf(Entry, SignatureName);

    const Verified = TEd25519.Verify(Key, Message, Signature);

    Assert.AreEqual(SpeccheckTotal, Cases.Count);
    Assert.AreEqual(Expected, Verified);
  finally
    Cases.Free;
  end;
end;

procedure TEd25519VectorTests.Verify_SignInputVectors_AllVerify;
begin
  const Tally = TallySignInput(False);

  const Summary = Tally.Summary(SignInputFile);
  TTestSupport.Log(Summary);
  Assert.AreEqual('', Tally.MismatchList);
  Assert.AreEqual(SignInputTotal, Tally.Verified, Summary);
end;

procedure TEd25519VectorTests.Verify_SignInputVectorsWithFlippedSignatureBit_NeverVerify;
begin
  const Tally = TallySignInput(True);

  const Summary = Tally.Summary(SignInputFile);
  Assert.AreEqual('', Tally.MismatchList);
  Assert.AreEqual(SignInputTotal, Tally.Total, Summary);
  Assert.AreEqual(0, Tally.Verified, Summary);
end;

function TEd25519VectorTests.TallySignInput(const DamagesSignature: Boolean): TVerificationTally;
begin
  Result := Default(TVerificationTally);

  const Document = TTestSupport.LoadJsonObject(SignInputFile);
  try
    const Tests = TTestSupport.ArrayOf(Document, 'tests');
    for var Index := 0 to Tests.Count - 1 do
    begin
      const Test    = TTestSupport.ObjectAt(Tests, Index);
      const Key     = TTestSupport.BytesOf(Test, 'publicKey');
      const Message = TTestSupport.BytesOf(Test, MessageName);
      var Signature := TTestSupport.BytesOf(Test, SignatureName);
      if DamagesSignature then
      begin
        const BitIndex = Index mod (Length(Signature) * BitsPerByte);
        Signature := TTestSupport.FlipBit(Signature, BitIndex);
      end;

      const Verified = TEd25519.Verify(Key, Message, Signature);

      Result.Add(Index.ToString, not DamagesSignature, Verified);
    end;
  finally
    Document.Free;
  end;
end;

end.
