unit Crypto4D.Ecdsa.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  Crypto4D.Ecdsa;

type
  [TestFixture]
  TEcdsaP256Tests = class
  private
    const
      KeyXHex   = '04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5';
      KeyYHex   = '87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d';
      RHex      = 'b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a';
      SHex      = '0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2';
      DerHex    = '3045022100b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a' +
                  '02200177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2';
      OrderHex  = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
      ZeroHex   = '0000000000000000000000000000000000000000000000000000000000000000';

    var
      FKey: TEcdsaP256PublicKey;
      FMessage: TBytes;

    function Bytes(const Hex: string): TBytes;

  public
    [SetupFixture]
    procedure SetupFixture;

    [Test]
    procedure VerifyDer_ValidSignature_ReturnsTrue;

    [Test]
    procedure VerifyRaw_ValidSignature_ReturnsTrue;

    [Test]
    procedure VerifyRaw_HighSValue_ReturnsTrue;

    [Test]
    procedure VerifyDer_ChangedMessage_ReturnsFalse;

    [Test]
    procedure VerifyDer_AnySignatureBitFlipped_ReturnsFalse;

    [Test]
    procedure VerifyDer_AnyTruncation_ReturnsFalse;

    [Test]
    [TestCase('Empty', '')]
    [TestCase('TrailingByte', '3006020101020101ff')]
    [TestCase('LongFormLength', '308106020101020101')]
    [TestCase('IndefiniteLength', '30800201010201010000')]
    [TestCase('PaddedInteger', '30070202000102' + '0101')]
    [TestCase('NegativeInteger', '3006020181020101')]
    [TestCase('EmptyInteger', '30050200020101')]
    [TestCase('ThreeIntegers', '3009020101020101020101')]
    [TestCase('NotASequence', '3106020101020101')]
    procedure VerifyDer_MalformedEncoding_ReturnsFalse(const SignatureHex: string);

    [Test]
    [TestCase('Empty', '0')]
    [TestCase('OneShort', '63')]
    [TestCase('OneLong', '65')]
    procedure VerifyRaw_SignatureOfWrongLength_ReturnsFalse(const SignatureLength: Integer);

    [Test]
    [TestCase('RIsZero', '0000000000000000000000000000000000000000000000000000000000000000,0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2')]
    [TestCase('SIsZero', 'b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a,0000000000000000000000000000000000000000000000000000000000000000')]
    [TestCase('RIsOrder', 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2')]
    [TestCase('SIsOrder', 'b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a,ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551')]
    procedure VerifyRaw_ValueOutOfRange_ReturnsFalse(const R: string; const S: string);

    [Test]
    procedure VerifyRaw_KeyNotOnCurve_ReturnsFalse;

    [Test]
    procedure VerifyRaw_KeyWithZeroCoordinates_ReturnsFalse;

    [Test]
    procedure VerifyRaw_KeyCoordinateNotBelowPrime_ReturnsFalse;

    [Test]
    procedure VerifyRaw_KeyNeverAssigned_RaisesArgumentError;

    [Test]
    [TestCase('ShortX', '31,32')]
    [TestCase('LongY', '32,33')]
    [TestCase('BothEmpty', '0,0')]
    procedure FromCoordinates_WrongLength_RaisesArgumentError(const XLength: Integer; const YLength: Integer);

    [Test]
    [TestCase('CompressedPrefix', '02,65')]
    [TestCase('TooShort', '04,64')]
    [TestCase('TooLong', '04,66')]
    procedure FromUncompressedPoint_WrongEncoding_RaisesArgumentError(const PrefixHex: string; const PointLength: Integer);

    [Test]
    procedure FromUncompressedPoint_ValidPoint_SplitsCoordinates;
  end;

implementation

uses
  Crypto4D.BigInteger,
  Crypto4D.Errors,
  Crypto4D.TestSupport;

function TEcdsaP256Tests.Bytes(const Hex: string): TBytes;
begin
  Result := TTestSupport.HexToBytes(Hex);
end;

procedure TEcdsaP256Tests.SetupFixture;
begin
  FKey     := TEcdsaP256PublicKey.FromCoordinates(Bytes(KeyXHex), Bytes(KeyYHex));
  FMessage := nil;
end;

procedure TEcdsaP256Tests.VerifyDer_ValidSignature_ReturnsTrue;
begin
  const Verified = TEcdsaP256.VerifyDer(FKey, FMessage, Bytes(DerHex));

  Assert.IsTrue(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_ValidSignature_ReturnsTrue;
begin
  const Verified = TEcdsaP256.VerifyRaw(FKey, FMessage, Bytes(RHex + SHex));

  Assert.IsTrue(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_HighSValue_ReturnsTrue;
begin
  const HighS      = TBigInteger.FromHex(OrderHex) - TBigInteger.FromHex(SHex);
  const HighSBytes = HighS.ToFixedBytes(TEcdsaP256PublicKey.CoordinateSize);
  const Signature  = Bytes(RHex) + HighSBytes;

  const Verified = TEcdsaP256.VerifyRaw(FKey, FMessage, Signature);

  Assert.IsTrue(Verified);
end;

procedure TEcdsaP256Tests.VerifyDer_ChangedMessage_ReturnsFalse;
begin
  const Verified = TEcdsaP256.VerifyDer(FKey, TBytes.Create(0), Bytes(DerHex));

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyDer_AnySignatureBitFlipped_ReturnsFalse;
begin
  const Signature = Bytes(DerHex);
  for var BitIndex := 0 to Length(Signature) * 8 - 1 do
  begin
    const Damaged = TTestSupport.FlipBit(Signature, BitIndex);

    const Verified = TEcdsaP256.VerifyDer(FKey, FMessage, Damaged);

    Assert.IsFalse(Verified, Format('bit %d', [BitIndex]));
  end;
end;

procedure TEcdsaP256Tests.VerifyDer_AnyTruncation_ReturnsFalse;
begin
  const Signature = Bytes(DerHex);
  for var KeptLength := 0 to Length(Signature) - 1 do
  begin
    const Truncated = Copy(Signature, 0, KeptLength);

    const Verified = TEcdsaP256.VerifyDer(FKey, FMessage, Truncated);

    Assert.IsFalse(Verified, Format('length %d', [KeptLength]));
  end;
end;

procedure TEcdsaP256Tests.VerifyDer_MalformedEncoding_ReturnsFalse(const SignatureHex: string);
begin
  const Verified = TEcdsaP256.VerifyDer(FKey, FMessage, Bytes(SignatureHex));

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_SignatureOfWrongLength_ReturnsFalse(const SignatureLength: Integer);
begin
  var Signature := Bytes(RHex + SHex);
  SetLength(Signature, SignatureLength);

  const Verified = TEcdsaP256.VerifyRaw(FKey, FMessage, Signature);

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_ValueOutOfRange_ReturnsFalse(const R: string; const S: string);
begin
  const Verified = TEcdsaP256.VerifyRaw(FKey, FMessage, Bytes(R + S));

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_KeyNotOnCurve_ReturnsFalse;
begin
  const DamagedY = TTestSupport.FlipBit(Bytes(KeyYHex), 0);
  const Key      = TEcdsaP256PublicKey.FromCoordinates(Bytes(KeyXHex), DamagedY);

  const Verified = TEcdsaP256.VerifyRaw(Key, FMessage, Bytes(RHex + SHex));

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_KeyWithZeroCoordinates_ReturnsFalse;
begin
  const Key = TEcdsaP256PublicKey.FromCoordinates(Bytes(ZeroHex), Bytes(ZeroHex));

  const Verified = TEcdsaP256.VerifyRaw(Key, FMessage, Bytes(RHex + SHex));

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_KeyCoordinateNotBelowPrime_ReturnsFalse;
begin
  const AllOnes = Bytes(string.Create('f', TEcdsaP256PublicKey.CoordinateSize * 2));
  const Key     = TEcdsaP256PublicKey.FromCoordinates(AllOnes, Bytes(KeyYHex));

  const Verified = TEcdsaP256.VerifyRaw(Key, FMessage, Bytes(RHex + SHex));

  Assert.IsFalse(Verified);
end;

procedure TEcdsaP256Tests.VerifyRaw_KeyNeverAssigned_RaisesArgumentError;
begin
  Assert.WillRaise(
    procedure
    begin
      TEcdsaP256.VerifyRaw(Default(TEcdsaP256PublicKey), FMessage, Bytes(RHex + SHex));
    end,
    ECrypto4DArgumentError);
end;

procedure TEcdsaP256Tests.FromCoordinates_WrongLength_RaisesArgumentError(const XLength: Integer; const YLength: Integer);
begin
  var X: TBytes;
  var Y: TBytes;
  SetLength(X, XLength);
  SetLength(Y, YLength);

  Assert.WillRaise(
    procedure
    begin
      TEcdsaP256PublicKey.FromCoordinates(X, Y);
    end,
    ECrypto4DArgumentError);
end;

procedure TEcdsaP256Tests.FromUncompressedPoint_WrongEncoding_RaisesArgumentError(const PrefixHex: string; const PointLength: Integer);
begin
  var Point := Bytes(PrefixHex + KeyXHex + KeyYHex);
  SetLength(Point, PointLength);

  Assert.WillRaise(
    procedure
    begin
      TEcdsaP256PublicKey.FromUncompressedPoint(Point);
    end,
    ECrypto4DArgumentError);
end;

procedure TEcdsaP256Tests.FromUncompressedPoint_ValidPoint_SplitsCoordinates;
begin
  const Key = TEcdsaP256PublicKey.FromUncompressedPoint(Bytes('04' + KeyXHex + KeyYHex));

  Assert.AreEqual(KeyXHex, TTestSupport.BytesToHex(Key.X));
  Assert.AreEqual(KeyYHex, TTestSupport.BytesToHex(Key.Y));
end;

end.
