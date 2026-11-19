unit Crypto4D.Ecdsa;

interface

uses
  System.SysUtils,
  Crypto4D.BigInteger;

type
  TEcdsaP256PublicKey = record
  private
    FX: TBytes;
    FY: TBytes;

  public
    const
      CoordinateSize        = 32;
      UncompressedPointSize = 65;
      UncompressedPrefix    = $04;

    class function FromCoordinates(const X, Y: TBytes): TEcdsaP256PublicKey; static;
    class function FromUncompressedPoint(const Point: TBytes): TEcdsaP256PublicKey; static;
    class function IsUncompressedPoint(const Point: TBytes): Boolean; static;

    property X: TBytes read FX;
    property Y: TBytes read FY;
  end;

  TEcdsaP256 = class
  private
    class procedure GuardPublicKey(const PublicKey: TEcdsaP256PublicKey); static;
    class function TryParseDerSignature(const Signature: TBytes; out R, S: TBigInteger): Boolean; static;
    class function VerifyValues(const PublicKey: TEcdsaP256PublicKey;
                                const Message: TBytes;
                                const R, S: TBigInteger): Boolean; static;

  public
    const
      RawSignatureSize = 64;

    class function VerifyDer(const PublicKey: TEcdsaP256PublicKey; const Message, Signature: TBytes): Boolean; static;
    class function VerifyRaw(const PublicKey: TEcdsaP256PublicKey; const Message, Signature: TBytes): Boolean; static;
  end;

implementation

uses
  Crypto4D.Errors,
  Crypto4D.Der,
  Crypto4D.Hash,
  Crypto4D.P256;

resourcestring
  InvalidCoordinateSize = 'A P-256 public key coordinate must be %d bytes, but X is %d and Y is %d bytes';
  InvalidPointEncoding  = 'A P-256 public key must be an uncompressed point of %d bytes that starts with 0x04';

class function TEcdsaP256PublicKey.FromCoordinates(const X, Y: TBytes): TEcdsaP256PublicKey;
begin
  const HasValidSizes = (Length(X) = CoordinateSize) and (Length(Y) = CoordinateSize);
  if not HasValidSizes then
    raise ECrypto4DArgumentError.CreateFmt(InvalidCoordinateSize, [CoordinateSize, Length(X), Length(Y)]);

  Result.FX := Copy(X);
  Result.FY := Copy(Y);
end;

class function TEcdsaP256PublicKey.FromUncompressedPoint(const Point: TBytes): TEcdsaP256PublicKey;
begin
  if not IsUncompressedPoint(Point) then
    raise ECrypto4DArgumentError.CreateFmt(InvalidPointEncoding, [UncompressedPointSize]);

  Result.FX := Copy(Point, 1, CoordinateSize);
  Result.FY := Copy(Point, 1 + CoordinateSize, CoordinateSize);
end;

class function TEcdsaP256PublicKey.IsUncompressedPoint(const Point: TBytes): Boolean;
begin
  Result := (Length(Point) = UncompressedPointSize) and (Point[0] = UncompressedPrefix);
end;

class function TEcdsaP256.VerifyDer(const PublicKey: TEcdsaP256PublicKey; const Message, Signature: TBytes): Boolean;
begin
  GuardPublicKey(PublicKey);

  var R: TBigInteger;
  var S: TBigInteger;
  if not TryParseDerSignature(Signature, R, S) then
    Exit(False);

  Result := VerifyValues(PublicKey, Message, R, S);
end;

class function TEcdsaP256.VerifyRaw(const PublicKey: TEcdsaP256PublicKey; const Message, Signature: TBytes): Boolean;
begin
  GuardPublicKey(PublicKey);

  const HasValidSize = (Length(Signature) = RawSignatureSize);
  if not HasValidSize then
    Exit(False);

  const ValueSize = RawSignatureSize div 2;
  const RBytes    = Copy(Signature, 0, ValueSize);
  const SBytes    = Copy(Signature, ValueSize, ValueSize);
  const R         = TBigInteger.FromBytes(RBytes);
  const S         = TBigInteger.FromBytes(SBytes);

  Result := VerifyValues(PublicKey, Message, R, S);
end;

class procedure TEcdsaP256.GuardPublicKey(const PublicKey: TEcdsaP256PublicKey);
begin
  const XSize = Length(PublicKey.X);
  const YSize = Length(PublicKey.Y);
  const HasValidSizes = (XSize = TEcdsaP256PublicKey.CoordinateSize) and (YSize = TEcdsaP256PublicKey.CoordinateSize);
  if not HasValidSizes then
    raise ECrypto4DArgumentError.CreateFmt(InvalidCoordinateSize, [TEcdsaP256PublicKey.CoordinateSize, XSize, YSize]);
end;

class function TEcdsaP256.TryParseDerSignature(const Signature: TBytes; out R, S: TBigInteger): Boolean;
begin
  R := TBigInteger.Zero;
  S := TBigInteger.Zero;

  var Outer := TDerReader.Create(Signature);
  var Sequence: TDerElement;
  if not Outer.TryReadOnly(TDerTag.Sequence, Sequence) then
    Exit(False);

  var Inner := TDerReader.Create(Sequence.Content);
  var RElement: TDerElement;
  var SElement: TDerElement;
  const HasTwoIntegers = Inner.TryReadTagged(TDerTag.Integer, RElement) and
                         Inner.TryReadOnly(TDerTag.Integer, SElement);
  if not HasTwoIntegers then
    Exit(False);

  var RBytes: TBytes;
  var SBytes: TBytes;
  const AreUnsigned = RElement.TryGetUnsignedInteger(RBytes) and SElement.TryGetUnsignedInteger(SBytes);
  if not AreUnsigned then
    Exit(False);

  R      := TBigInteger.FromBytes(RBytes);
  S      := TBigInteger.FromBytes(SBytes);
  Result := True;
end;

class function TEcdsaP256.VerifyValues(const PublicKey: TEcdsaP256PublicKey;
                                       const Message: TBytes;
                                       const R, S: TBigInteger): Boolean;
begin
  const Curve   = TP256Curve.Create;
  const KeyX    = TBigInteger.FromBytes(PublicKey.X);
  const KeyY    = TBigInteger.FromBytes(PublicKey.Y);
  if not Curve.IsOnCurve(KeyX, KeyY) then
    Exit(False);

  const Order = Curve.Order;
  const ValuesInRange = (not R.IsZero) and (R < Order) and
                        (not S.IsZero) and (S < Order);
  if not ValuesInRange then
    Exit(False);

  const Digest          = TCryptoHash.Sha256(Message);
  const DigestValue     = TBigInteger.FromBytes(Digest);
  const SInverse        = S.ModInverse(Order);
  const GeneratorScalar = (DigestValue * SInverse) mod Order;
  const KeyScalar       = (R * SInverse) mod Order;

  const KeyPoint = Curve.AffinePoint(KeyX, KeyY);
  const Combined = Curve.MultiplyTwo(GeneratorScalar, KeyScalar, KeyPoint);

  var CombinedX: TBigInteger;
  if not Curve.TryGetAffineX(Combined, CombinedX) then
    Exit(False);

  const Candidate = CombinedX mod Order;
  Result := (Candidate = R);
end;

end.
