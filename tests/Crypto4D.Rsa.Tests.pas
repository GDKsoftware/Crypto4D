unit Crypto4D.Rsa.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework;

type
  [TestFixture]
  TRsaPkcs1Sha256Tests = class
  private
    const
      WycheproofFile = 'wycheproof/rsa_signature_2048_sha256_test.json';
      ModulusBytes   = 256;
      GroupsName     = 'testGroups';
      TestsName      = 'tests';
      ModulusName    = 'publicKey.modulus';
      ExponentName   = 'publicKey.publicExponent';
      MessageName    = 'msg';
      SignatureName  = 'sig';

    var
      FModulus: TBytes;
      FExponent: TBytes;
      FMessage: TBytes;
      FSignature: TBytes;

    function OddWithHighestBit(const HighestBit: Integer): TBytes;
    function EvenModulus: TBytes;

  public
    [SetupFixture]
    procedure SetupFixture;

    [Test]
    procedure Verify_ValidSignature_ReturnsTrue;

    [Test]
    procedure Verify_ChangedMessage_ReturnsFalse;

    [Test]
    procedure Verify_SignatureBitsFlipped_ReturnFalse;

    [Test]
    [TestCase('Empty', '0')]
    [TestCase('OneShort', '255')]
    [TestCase('OneLong', '257')]
    procedure Verify_SignatureOfWrongLength_ReturnsFalse(const SignatureLength: Integer);

    [Test]
    procedure Verify_SignatureEqualToModulus_ReturnsFalse;

    [Test]
    procedure Verify_KeyNeverAssigned_RaisesArgumentError;

    [Test]
    [TestCase('Bits1024', '1023')]
    [TestCase('Bits2047', '2046')]
    [TestCase('Bits8193', '8192')]
    [TestCase('Bits16384', '16383')]
    procedure Create_UnsupportedModulusSize_RaisesArgumentError(const HighestBit: Integer);

    [Test]
    [TestCase('Bits2048', '2047')]
    [TestCase('Bits8192', '8191')]
    procedure Create_ModulusAtSizeLimit_IsAccepted(const HighestBit: Integer);

    [Test]
    procedure Create_ModulusWithLeadingZeros_CountsSignificantBits;

    [Test]
    procedure Create_EvenModulus_RaisesArgumentError;

    [Test]
    procedure IsSupportedModulus_EvenModulus_ReturnsFalse;

    [Test]
    [TestCase('Empty', '')]
    [TestCase('Zero', '00')]
    [TestCase('One', '01')]
    [TestCase('Two', '02')]
    [TestCase('Even', '010000')]
    [TestCase('TwoToThe33PlusOne', '0200000001')]
    [TestCase('TwoToThe64MinusOne', 'ffffffffffffffff')]
    [TestCase('TwoToThe64PlusOne', '010000000000000001')]
    procedure Create_UnsupportedExponent_RaisesArgumentError(const ExponentHex: string);

    [Test]
    [TestCase('Three', '03')]
    [TestCase('F4', '010001')]
    [TestCase('F4WithLeadingZeros', '0000010001')]
    [TestCase('TwoToThe33MinusOne', '01ffffffff')]
    procedure Create_SupportedExponent_IsAccepted(const ExponentHex: string);

    [Test]
    procedure Verify_ExponentThree_ReturnsTrue;

    [Test]
    procedure Verify_OtherOddExponent_ReturnsFalse;
  end;

implementation

uses
  Crypto4D.BigInteger,
  Crypto4D.Errors,
  Crypto4D.Rsa,
  Crypto4D.TestSupport;

procedure TRsaPkcs1Sha256Tests.SetupFixture;
begin
  const Document = TTestSupport.LoadJsonObject(WycheproofFile);
  try
    const Groups = TTestSupport.ArrayOf(Document, GroupsName);
    const Group  = TTestSupport.ObjectAt(Groups, 0);
    const Tests  = TTestSupport.ArrayOf(Group, TestsName);
    const Test   = TTestSupport.ObjectAt(Tests, 0);

    FModulus   := TTestSupport.BytesOf(Group, ModulusName);
    FExponent  := TTestSupport.BytesOf(Group, ExponentName);
    FMessage   := TTestSupport.BytesOf(Test, MessageName);
    FSignature := TTestSupport.BytesOf(Test, SignatureName);
  finally
    Document.Free;
  end;
end;

function TRsaPkcs1Sha256Tests.OddWithHighestBit(const HighestBit: Integer): TBytes;
begin
  const Value = (TBigInteger.One shl HighestBit) + TBigInteger.One;
  Result := Value.ToBytes;
end;

function TRsaPkcs1Sha256Tests.EvenModulus: TBytes;
begin
  const LowestBit = (Length(FModulus) - 1) * 8;
  Result := TTestSupport.FlipBit(FModulus, LowestBit);
end;

procedure TRsaPkcs1Sha256Tests.Verify_ValidSignature_ReturnsTrue;
begin
  const Key = TRsaPublicKey.Create(FModulus, FExponent);

  const Verified = TRsaPkcs1Sha256.Verify(Key, FMessage, FSignature);

  Assert.IsTrue(Verified);
end;

procedure TRsaPkcs1Sha256Tests.Verify_ChangedMessage_ReturnsFalse;
begin
  const Key     = TRsaPublicKey.Create(FModulus, FExponent);
  const Changed = FMessage + TBytes.Create(0);

  const Verified = TRsaPkcs1Sha256.Verify(Key, Changed, FSignature);

  Assert.IsFalse(Verified);
end;

procedure TRsaPkcs1Sha256Tests.Verify_SignatureBitsFlipped_ReturnFalse;
begin
  const Key = TRsaPublicKey.Create(FModulus, FExponent);
  for var ByteIndex := 0 to High(FSignature) do
  begin
    const BitIndex = ByteIndex * 8 + (ByteIndex mod 8);
    const Damaged  = TTestSupport.FlipBit(FSignature, BitIndex);

    const Verified = TRsaPkcs1Sha256.Verify(Key, FMessage, Damaged);

    Assert.IsFalse(Verified, Format('bit %d', [BitIndex]));
  end;
end;

procedure TRsaPkcs1Sha256Tests.Verify_SignatureOfWrongLength_ReturnsFalse(const SignatureLength: Integer);
begin
  const Key = TRsaPublicKey.Create(FModulus, FExponent);
  var Resized := Copy(FSignature);
  SetLength(Resized, SignatureLength);

  const Verified = TRsaPkcs1Sha256.Verify(Key, FMessage, Resized);

  Assert.IsFalse(Verified);
end;

procedure TRsaPkcs1Sha256Tests.Verify_SignatureEqualToModulus_ReturnsFalse;
begin
  const Key       = TRsaPublicKey.Create(FModulus, FExponent);
  const Modulus   = TBigInteger.FromBytes(FModulus);
  const Signature = Modulus.ToFixedBytes(ModulusBytes);

  const Verified = TRsaPkcs1Sha256.Verify(Key, FMessage, Signature);

  Assert.IsFalse(Verified);
end;

procedure TRsaPkcs1Sha256Tests.Verify_KeyNeverAssigned_RaisesArgumentError;
begin
  Assert.WillRaise(
    procedure
    begin
      TRsaPkcs1Sha256.Verify(Default(TRsaPublicKey), FMessage, FSignature);
    end,
    ECrypto4DArgumentError);
end;

procedure TRsaPkcs1Sha256Tests.Create_UnsupportedModulusSize_RaisesArgumentError(const HighestBit: Integer);
begin
  const Modulus = OddWithHighestBit(HighestBit);

  Assert.WillRaise(
    procedure
    begin
      TRsaPublicKey.Create(Modulus, FExponent);
    end,
    ECrypto4DArgumentError);
end;

procedure TRsaPkcs1Sha256Tests.Create_ModulusAtSizeLimit_IsAccepted(const HighestBit: Integer);
begin
  const Modulus = OddWithHighestBit(HighestBit);

  const Key = TRsaPublicKey.Create(Modulus, FExponent);

  const ExpectedHex = TTestSupport.BytesToHex(Modulus);
  const ActualHex   = TTestSupport.BytesToHex(Key.Modulus);
  Assert.AreEqual(ExpectedHex, ActualHex);
end;

procedure TRsaPkcs1Sha256Tests.Create_ModulusWithLeadingZeros_CountsSignificantBits;
begin
  var Padded: TBytes;
  SetLength(Padded, ModulusBytes);
  Padded[1] := $FF;

  Assert.WillRaise(
    procedure
    begin
      TRsaPublicKey.Create(Padded, FExponent);
    end,
    ECrypto4DArgumentError);
end;

procedure TRsaPkcs1Sha256Tests.Create_EvenModulus_RaisesArgumentError;
begin
  const Modulus = EvenModulus;

  Assert.WillRaise(
    procedure
    begin
      TRsaPublicKey.Create(Modulus, FExponent);
    end,
    ECrypto4DArgumentError);
end;

procedure TRsaPkcs1Sha256Tests.IsSupportedModulus_EvenModulus_ReturnsFalse;
begin
  const Modulus = EvenModulus;

  const OddIsSupported  = TRsaPublicKey.IsSupportedModulus(FModulus);
  const EvenIsSupported = TRsaPublicKey.IsSupportedModulus(Modulus);

  Assert.IsTrue(OddIsSupported);
  Assert.IsFalse(EvenIsSupported);
end;

procedure TRsaPkcs1Sha256Tests.Create_UnsupportedExponent_RaisesArgumentError(const ExponentHex: string);
begin
  const Exponent = TTestSupport.HexToBytes(ExponentHex);

  Assert.WillRaise(
    procedure
    begin
      TRsaPublicKey.Create(FModulus, Exponent);
    end,
    ECrypto4DArgumentError);
end;

procedure TRsaPkcs1Sha256Tests.Create_SupportedExponent_IsAccepted(const ExponentHex: string);
begin
  const Exponent = TTestSupport.HexToBytes(ExponentHex);

  const Key = TRsaPublicKey.Create(FModulus, Exponent);

  const ActualHex = TTestSupport.BytesToHex(Key.Exponent);
  Assert.AreEqual(ExponentHex, ActualHex);
end;

procedure TRsaPkcs1Sha256Tests.Verify_ExponentThree_ReturnsTrue;
begin
  const Document = TTestSupport.LoadJsonObject(WycheproofFile);
  try
    const Groups    = TTestSupport.ArrayOf(Document, GroupsName);
    const Group     = TTestSupport.ObjectAt(Groups, 1);
    const Tests     = TTestSupport.ArrayOf(Group, TestsName);
    const Test      = TTestSupport.ObjectAt(Tests, 0);
    const Modulus   = TTestSupport.BytesOf(Group, ModulusName);
    const Exponent  = TTestSupport.BytesOf(Group, ExponentName);
    const Message   = TTestSupport.BytesOf(Test, MessageName);
    const Signature = TTestSupport.BytesOf(Test, SignatureName);
    const Key       = TRsaPublicKey.Create(Modulus, Exponent);

    const Verified = TRsaPkcs1Sha256.Verify(Key, Message, Signature);

    const ExponentHex = TTestSupport.BytesToHex(Exponent);
    const Outcome     = Test.GetValue<string>('result');
    Assert.AreEqual('03', ExponentHex);
    Assert.AreEqual('valid', Outcome);
    Assert.IsTrue(Verified);
  finally
    Document.Free;
  end;
end;

procedure TRsaPkcs1Sha256Tests.Verify_OtherOddExponent_ReturnsFalse;
begin
  const OtherExponent = TBytes.Create(3);
  const Key           = TRsaPublicKey.Create(FModulus, OtherExponent);

  const Verified = TRsaPkcs1Sha256.Verify(Key, FMessage, FSignature);

  Assert.IsFalse(Verified);
end;

end.
