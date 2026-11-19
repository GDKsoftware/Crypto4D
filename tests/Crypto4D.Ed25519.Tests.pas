unit Crypto4D.Ed25519.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework;

type
  [TestFixture]
  TEd25519Tests = class
  private
    const
      Rfc8032File         = 'rfc8032/ed25519.json';
      OrderHex            = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';
      IdentityKeyHex      = '0100000000000000000000000000000000000000000000000000000000000000';
      NonCanonicalZeroHex = 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f';
      NegativeZeroXHex    = '0100000000000000000000000000000000000000000000000000000000000080';
      ScalarSize          = 32;

    var
      FPublicKey: TBytes;
      FMessage: TBytes;
      FSignature: TBytes;

    function ReverseBytes(const Bytes: TBytes): TBytes;
    function SignatureWithScalarPlusOrder: TBytes;

  public
    [SetupFixture]
    procedure SetupFixture;

    [Test]
    procedure Verify_Rfc8032Vectors_ReturnTrue;

    [Test]
    procedure Verify_ChangedMessage_ReturnsFalse;

    [Test]
    procedure Verify_AnySignatureBitFlipped_ReturnsFalse;

    [Test]
    procedure Verify_AnyPublicKeyBitFlipped_ReturnsFalse;

    [Test]
    [TestCase('Empty', '0')]
    [TestCase('OneShort', '63')]
    [TestCase('OneLong', '65')]
    procedure Verify_SignatureOfWrongLength_ReturnsFalse(const SignatureLength: Integer);

    [Test]
    [TestCase('Empty', '0')]
    [TestCase('OneShort', '31')]
    [TestCase('OneLong', '33')]
    procedure Verify_PublicKeyOfWrongLength_RaisesArgumentError(const KeyLength: Integer);

    [Test]
    procedure Verify_ScalarNotBelowOrder_ReturnsFalse;

    [Test]
    procedure Verify_IdentityPublicKey_ReturnsFalse;

    [Test]
    [TestCase('YEqualToPrime', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')]
    [TestCase('NegativeZeroX', '0100000000000000000000000000000000000000000000000000000000000080')]
    [TestCase('NotOnCurve', '0200000000000000000000000000000000000000000000000000000000000000')]
    procedure Verify_UndecodablePublicKey_ReturnsFalse(const KeyHex: string);
  end;

implementation

uses
  Crypto4D.BigInteger,
  Crypto4D.Ed25519,
  Crypto4D.Errors,
  Crypto4D.TestSupport;

procedure TEd25519Tests.SetupFixture;
begin
  const Document = TTestSupport.LoadJsonObject(Rfc8032File);
  try
    const Vectors = TTestSupport.ArrayOf(Document, 'vectors');
    const Vector  = TTestSupport.ObjectAt(Vectors, 2);
    FPublicKey := TTestSupport.HexToBytes(Vector.GetValue<string>('publicKey'));
    FMessage   := TTestSupport.HexToBytes(Vector.GetValue<string>('message'));
    FSignature := TTestSupport.HexToBytes(Vector.GetValue<string>('signature'));
  finally
    Document.Free;
  end;
end;

function TEd25519Tests.ReverseBytes(const Bytes: TBytes): TBytes;
begin
  const Count = Length(Bytes);
  SetLength(Result, Count);
  for var Index := 0 to Count - 1 do
  begin
    Result[Index] := Bytes[Count - 1 - Index];
  end;
end;

function TEd25519Tests.SignatureWithScalarPlusOrder: TBytes;
begin
  const ScalarBytes  = Copy(FSignature, ScalarSize, ScalarSize);
  const Scalar       = TBigInteger.FromBytes(ReverseBytes(ScalarBytes));
  const Raised       = Scalar + TBigInteger.FromHex(OrderHex);
  const RaisedBytes  = ReverseBytes(Raised.ToFixedBytes(ScalarSize));

  Result := Copy(FSignature, 0, ScalarSize) + RaisedBytes;
end;

procedure TEd25519Tests.Verify_Rfc8032Vectors_ReturnTrue;
begin
  const Document = TTestSupport.LoadJsonObject(Rfc8032File);
  try
    const Vectors = TTestSupport.ArrayOf(Document, 'vectors');
    for var Index := 0 to Vectors.Count - 1 do
    begin
      const Vector    = TTestSupport.ObjectAt(Vectors, Index);
      const PublicKey = TTestSupport.HexToBytes(Vector.GetValue<string>('publicKey'));
      const Message   = TTestSupport.HexToBytes(Vector.GetValue<string>('message'));
      const Signature = TTestSupport.HexToBytes(Vector.GetValue<string>('signature'));

      const Verified = TEd25519.Verify(PublicKey, Message, Signature);

      Assert.IsTrue(Verified, Vector.GetValue<string>('name'));
    end;

    Assert.AreEqual(5, Vectors.Count);
  finally
    Document.Free;
  end;
end;

procedure TEd25519Tests.Verify_ChangedMessage_ReturnsFalse;
begin
  const Changed = TTestSupport.FlipBit(FMessage, 0);

  const Verified = TEd25519.Verify(FPublicKey, Changed, FSignature);

  Assert.IsFalse(Verified);
end;

procedure TEd25519Tests.Verify_AnySignatureBitFlipped_ReturnsFalse;
begin
  for var BitIndex := 0 to Length(FSignature) * 8 - 1 do
  begin
    const Damaged = TTestSupport.FlipBit(FSignature, BitIndex);

    const Verified = TEd25519.Verify(FPublicKey, FMessage, Damaged);

    Assert.IsFalse(Verified, Format('bit %d', [BitIndex]));
  end;
end;

procedure TEd25519Tests.Verify_AnyPublicKeyBitFlipped_ReturnsFalse;
begin
  for var BitIndex := 0 to Length(FPublicKey) * 8 - 1 do
  begin
    const Damaged = TTestSupport.FlipBit(FPublicKey, BitIndex);

    const Verified = TEd25519.Verify(Damaged, FMessage, FSignature);

    Assert.IsFalse(Verified, Format('bit %d', [BitIndex]));
  end;
end;

procedure TEd25519Tests.Verify_SignatureOfWrongLength_ReturnsFalse(const SignatureLength: Integer);
begin
  var Resized := Copy(FSignature);
  SetLength(Resized, SignatureLength);

  const Verified = TEd25519.Verify(FPublicKey, FMessage, Resized);

  Assert.IsFalse(Verified);
end;

procedure TEd25519Tests.Verify_PublicKeyOfWrongLength_RaisesArgumentError(const KeyLength: Integer);
begin
  var Resized := Copy(FPublicKey);
  SetLength(Resized, KeyLength);

  Assert.WillRaise(
    procedure
    begin
      TEd25519.Verify(Resized, FMessage, FSignature);
    end,
    ECrypto4DArgumentError);
end;

procedure TEd25519Tests.Verify_ScalarNotBelowOrder_ReturnsFalse;
begin
  const Malleated = SignatureWithScalarPlusOrder;

  const Verified = TEd25519.Verify(FPublicKey, FMessage, Malleated);

  Assert.IsFalse(Verified);
end;

procedure TEd25519Tests.Verify_IdentityPublicKey_ReturnsFalse;
begin
  const IdentityKey = TTestSupport.HexToBytes(IdentityKeyHex);
  var Forgery: TBytes;
  SetLength(Forgery, TEd25519.SignatureSize);
  Forgery[0] := 1;

  const Verified = TEd25519.Verify(IdentityKey, FMessage, Forgery);

  Assert.IsFalse(Verified);
end;

procedure TEd25519Tests.Verify_UndecodablePublicKey_ReturnsFalse(const KeyHex: string);
begin
  const Key = TTestSupport.HexToBytes(KeyHex);

  const Verified = TEd25519.Verify(Key, FMessage, FSignature);

  Assert.IsFalse(Verified);
end;

end.
