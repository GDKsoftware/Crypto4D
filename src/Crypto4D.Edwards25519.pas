unit Crypto4D.Edwards25519;

interface

uses
  System.SysUtils,
  Crypto4D.BigInteger,
  Crypto4D.PrimeField;

type
  /// <summary>
  ///   A point on edwards25519 in extended coordinates: the affine point is (X / Z, Y / Z) and T is X * Y / Z.
  /// </summary>
  TEdwardsPoint = record
  private
    FX: TBigInteger;
    FY: TBigInteger;
    FZ: TBigInteger;
    FT: TBigInteger;

  public
    /// <summary>
    ///   Creates a point from extended coordinates. The coordinates are not checked.
    /// </summary>
    class function Create(const X, Y, Z, T: TBigInteger): TEdwardsPoint; static;

    property X: TBigInteger read FX;
    property Y: TBigInteger read FY;
    property Z: TBigInteger read FZ;
    property T: TBigInteger read FT;
  end;

  /// <summary>
  ///   The twisted Edwards curve edwards25519 of RFC 8032, with the point arithmetic that signature verification
  ///   needs. Not constant time.
  /// </summary>
  TEdwards25519Curve = record
  private
    const
      PrimeHex        = '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed';
      OrderHex        = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';
      CoefficientDHex = '52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3';
      SqrtMinusOneHex = '2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0';
      BasePointXHex   = '216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a';
      BasePointYHex   = '6666666666666666666666666666666666666666666666666666666666666658';
      SignMask        = $80;
      ValueMask       = $7F;
      SquareRootShift = 3;
      SquareRootBias  = 5;
      CofactorDoublings = 3;

    var
      FField: TPrimeField;
      FOrder: TBigInteger;
      FD: TBigInteger;
      FTwoD: TBigInteger;
      FSqrtMinusOne: TBigInteger;
      FSquareRootExponent: TBigInteger;
      FBasePoint: TEdwardsPoint;

    function AffinePoint(const X, Y: TBigInteger): TEdwardsPoint;
    function TryRecoverX(const Y: TBigInteger; out X: TBigInteger): Boolean;
    function SelectTerm(const HasFirst, HasSecond: Boolean;
                        const First, Second, Both: TEdwardsPoint): TEdwardsPoint;

  public
    const
      EncodedSize = 32;

    /// <summary>
    ///   Creates the curve with its parameters.
    /// </summary>
    class function Create: TEdwards25519Curve; static;

    /// <summary>
    ///   Reads an unsigned integer from little-endian bytes of any length.
    /// </summary>
    class function LittleEndianToInteger(const Bytes: TBytes): TBigInteger; static;

    /// <summary>
    ///   Returns the neutral point (0, 1).
    /// </summary>
    function Identity: TEdwardsPoint;

    /// <summary>
    ///   Decodes a point as RFC 8032 section 5.1.3 describes.
    /// </summary>
    /// <param name="Encoded">32 bytes: y in little-endian with the sign of x in the top bit.</param>
    /// <param name="Point">Receives the point, or the neutral point when decoding fails.</param>
    /// <returns>False when Encoded is not 32 bytes, y is not below the field prime, no x exists for this y, or x is
    ///   zero while the sign bit is set.</returns>
    function TryDecode(const Encoded: TBytes; out Point: TEdwardsPoint): Boolean;

    /// <summary>
    ///   Encodes a point as 32 bytes: y in little-endian with the sign of x in the top bit.
    /// </summary>
    function Encode(const Point: TEdwardsPoint): TBytes;

    /// <summary>
    ///   Adds two points on the curve. The formula is complete: it holds for every pair of points.
    /// </summary>
    function Add(const Left, Right: TEdwardsPoint): TEdwardsPoint;

    /// <summary>
    ///   Adds a point on the curve to itself.
    /// </summary>
    function Double(const Point: TEdwardsPoint): TEdwardsPoint;

    /// <summary>
    ///   Returns the opposite point (-x, y).
    /// </summary>
    function Negate(const Point: TEdwardsPoint): TEdwardsPoint;

    /// <summary>
    ///   Computes BaseScalar * B + PointScalar * Point, where B is the base point.
    /// </summary>
    /// <param name="BaseScalar">Scalar for the base point; only its lowest 253 bits are used.</param>
    /// <param name="PointScalar">Scalar for Point; only its lowest 253 bits are used.</param>
    /// <param name="Point">A point on the curve.</param>
    function MultiplyTwo(const BaseScalar: TBigInteger;
                         const PointScalar: TBigInteger;
                         const Point: TEdwardsPoint): TEdwardsPoint;

    /// <summary>
    ///   True when the point is the neutral point.
    /// </summary>
    function IsIdentity(const Point: TEdwardsPoint): Boolean;

    /// <summary>
    ///   True when 8 times the point is the neutral point, so the point is one of the eight points of small order.
    /// </summary>
    function HasSmallOrder(const Point: TEdwardsPoint): Boolean;

    /// <summary>
    ///   Order L of the base point.
    /// </summary>
    property Order: TBigInteger read FOrder;
  end;

implementation

class function TEdwardsPoint.Create(const X, Y, Z, T: TBigInteger): TEdwardsPoint;
begin
  Result.FX := X;
  Result.FY := Y;
  Result.FZ := Z;
  Result.FT := T;
end;

class function TEdwards25519Curve.Create: TEdwards25519Curve;
begin
  const Prime      = TBigInteger.FromHex(PrimeHex);
  const Field      = TPrimeField.Create(Prime);
  const D          = TBigInteger.FromHex(CoefficientDHex);
  const BasePointX = TBigInteger.FromHex(BasePointXHex);
  const BasePointY = TBigInteger.FromHex(BasePointYHex);
  const Bias       = TBigInteger.FromUInt64(SquareRootBias);
  const Biased     = Prime - Bias;

  Result.FField              := Field;
  Result.FOrder              := TBigInteger.FromHex(OrderHex);
  Result.FD                  := D;
  Result.FTwoD               := Field.Double(D);
  Result.FSqrtMinusOne       := TBigInteger.FromHex(SqrtMinusOneHex);
  Result.FSquareRootExponent := Biased shr SquareRootShift;
  Result.FBasePoint          := Result.AffinePoint(BasePointX, BasePointY);
end;

class function TEdwards25519Curve.LittleEndianToInteger(const Bytes: TBytes): TBigInteger;
begin
  const Count = Length(Bytes);
  var BigEndian: TBytes;
  SetLength(BigEndian, Count);
  for var Index := 0 to Count - 1 do
  begin
    BigEndian[Index] := Bytes[Count - 1 - Index];
  end;

  Result := TBigInteger.FromBytes(BigEndian);
end;

function TEdwards25519Curve.TryDecode(const Encoded: TBytes; out Point: TEdwardsPoint): Boolean;
begin
  Point := Identity;
  const HasValidSize = (Length(Encoded) = EncodedSize);
  if not HasValidSize then
    Exit(False);

  const LastIndex   = EncodedSize - 1;
  const XIsOdd      = ((Encoded[LastIndex] and SignMask) <> 0);
  var YBytes := Copy(Encoded);
  YBytes[LastIndex] := YBytes[LastIndex] and ValueMask;

  const Y = LittleEndianToInteger(YBytes);
  if not FField.Contains(Y) then
    Exit(False);

  var X: TBigInteger;
  if not TryRecoverX(Y, X) then
    Exit(False);

  const IsNegativeZero = (X.IsZero and XIsOdd);
  if IsNegativeZero then
    Exit(False);

  const HasWrongSign = (X.IsOdd <> XIsOdd);
  if HasWrongSign then
    X := FField.Negate(X);

  Point  := AffinePoint(X, Y);
  Result := True;
end;

function TEdwards25519Curve.TryRecoverX(const Y: TBigInteger; out X: TBigInteger): Boolean;
begin
  X := TBigInteger.Zero;

  const YSquared    = FField.Square(Y);
  const Numerator   = FField.Subtract(YSquared, TBigInteger.One);
  const DYSquared   = FField.Multiply(FD, YSquared);
  const Denominator = FField.Add(DYSquared, TBigInteger.One);

  const DenominatorSqr   = FField.Square(Denominator);
  const DenominatorCube  = FField.Multiply(DenominatorSqr, Denominator);
  const DenominatorPow4  = FField.Square(DenominatorSqr);
  const DenominatorPow7  = FField.Multiply(DenominatorPow4, DenominatorCube);
  const PowerBase        = FField.Multiply(Numerator, DenominatorPow7);
  const Power            = FField.Power(PowerBase, FSquareRootExponent);
  const NumeratorTimes   = FField.Multiply(Numerator, DenominatorCube);
  const Candidate        = FField.Multiply(NumeratorTimes, Power);

  const CandidateSqr = FField.Square(Candidate);
  const Check        = FField.Multiply(Denominator, CandidateSqr);
  const IsRoot       = (Check = Numerator);
  if IsRoot then
  begin
    X := Candidate;
    Exit(True);
  end;

  const NegatedNumerator = FField.Negate(Numerator);
  const IsRootTimesI     = (Check = NegatedNumerator);
  if not IsRootTimesI then
    Exit(False);

  X      := FField.Multiply(Candidate, FSqrtMinusOne);
  Result := True;
end;

function TEdwards25519Curve.AffinePoint(const X, Y: TBigInteger): TEdwardsPoint;
begin
  const T = FField.Multiply(X, Y);
  Result := TEdwardsPoint.Create(X, Y, TBigInteger.One, T);
end;

function TEdwards25519Curve.Encode(const Point: TEdwardsPoint): TBytes;
begin
  const ZInverse = FField.Invert(Point.Z);
  const X        = FField.Multiply(Point.X, ZInverse);
  const Y        = FField.Multiply(Point.Y, ZInverse);
  const BigEndian = Y.ToFixedBytes(EncodedSize);

  SetLength(Result, EncodedSize);
  for var Index := 0 to EncodedSize - 1 do
  begin
    Result[Index] := BigEndian[EncodedSize - 1 - Index];
  end;

  if X.IsOdd then
    Result[EncodedSize - 1] := Result[EncodedSize - 1] or SignMask;
end;

function TEdwards25519Curve.Negate(const Point: TEdwardsPoint): TEdwardsPoint;
begin
  const NegatedX = FField.Negate(Point.X);
  const NegatedT = FField.Negate(Point.T);

  Result := TEdwardsPoint.Create(NegatedX, Point.Y, Point.Z, NegatedT);
end;

function TEdwards25519Curve.MultiplyTwo(const BaseScalar: TBigInteger;
                                        const PointScalar: TBigInteger;
                                        const Point: TEdwardsPoint): TEdwardsPoint;
begin
  const Both     = Add(FBasePoint, Point);
  const Neutral  = Identity;
  const BitCount = FOrder.BitLength;

  Result := Neutral;
  for var BitIndex := BitCount - 1 downto 0 do
  begin
    const HasBase  = BaseScalar.TestBit(BitIndex);
    const HasPoint = PointScalar.TestBit(BitIndex);
    const Term     = SelectTerm(HasBase, HasPoint, FBasePoint, Point, Both);

    Result := Double(Result);
    const HasTerm = (HasBase or HasPoint);
    if HasTerm then
      Result := Add(Result, Term);
  end;
end;

function TEdwards25519Curve.SelectTerm(const HasFirst, HasSecond: Boolean;
                                       const First, Second, Both: TEdwardsPoint): TEdwardsPoint;
begin
  if HasFirst and HasSecond then
    Exit(Both);
  if HasFirst then
    Exit(First);
  if HasSecond then
    Exit(Second);

  Result := Identity;
end;

function TEdwards25519Curve.HasSmallOrder(const Point: TEdwardsPoint): Boolean;
begin
  var Multiple := Point;
  for var Doubling := 1 to CofactorDoublings do
  begin
    Multiple := Double(Multiple);
  end;

  Result := IsIdentity(Multiple);
end;

function TEdwards25519Curve.IsIdentity(const Point: TEdwardsPoint): Boolean;
begin
  Result := Point.X.IsZero and (Point.Y = Point.Z);
end;

function TEdwards25519Curve.Add(const Left, Right: TEdwardsPoint): TEdwardsPoint;
begin
  const LeftDifference  = FField.Subtract(Left.Y, Left.X);
  const RightDifference = FField.Subtract(Right.Y, Right.X);
  const LeftSum         = FField.Add(Left.Y, Left.X);
  const RightSum        = FField.Add(Right.Y, Right.X);
  const A               = FField.Multiply(LeftDifference, RightDifference);
  const B               = FField.Multiply(LeftSum, RightSum);

  const TProduct = FField.Multiply(Left.T, Right.T);
  const C        = FField.Multiply(TProduct, FTwoD);
  const ZProduct = FField.Multiply(Left.Z, Right.Z);
  const D        = FField.Double(ZProduct);

  const E = FField.Subtract(B, A);
  const F = FField.Subtract(D, C);
  const G = FField.Add(D, C);
  const H = FField.Add(B, A);

  const ResultX = FField.Multiply(E, F);
  const ResultY = FField.Multiply(G, H);
  const ResultZ = FField.Multiply(F, G);
  const ResultT = FField.Multiply(E, H);

  Result := TEdwardsPoint.Create(ResultX, ResultY, ResultZ, ResultT);
end;

function TEdwards25519Curve.Double(const Point: TEdwardsPoint): TEdwardsPoint;
begin
  const A       = FField.Square(Point.X);
  const B       = FField.Square(Point.Y);
  const ZSqr    = FField.Square(Point.Z);
  const C       = FField.Double(ZSqr);
  const H       = FField.Add(A, B);
  const XPlusY  = FField.Add(Point.X, Point.Y);
  const SumSqr  = FField.Square(XPlusY);
  const E       = FField.Subtract(H, SumSqr);
  const G       = FField.Subtract(A, B);
  const F       = FField.Add(C, G);

  const ResultX = FField.Multiply(E, F);
  const ResultY = FField.Multiply(G, H);
  const ResultZ = FField.Multiply(F, G);
  const ResultT = FField.Multiply(E, H);

  Result := TEdwardsPoint.Create(ResultX, ResultY, ResultZ, ResultT);
end;

function TEdwards25519Curve.Identity: TEdwardsPoint;
begin
  Result := TEdwardsPoint.Create(TBigInteger.Zero, TBigInteger.One, TBigInteger.One, TBigInteger.Zero);
end;

end.
