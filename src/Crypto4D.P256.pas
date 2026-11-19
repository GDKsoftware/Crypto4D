unit Crypto4D.P256;

interface

uses
  Crypto4D.BigInteger,
  Crypto4D.PrimeField;

type
  TP256Point = record
  private
    FX: TBigInteger;
    FY: TBigInteger;
    FZ: TBigInteger;

  public
    class function Create(const X, Y, Z: TBigInteger): TP256Point; static;
    class function Infinity: TP256Point; static;

    function IsInfinity: Boolean;

    property X: TBigInteger read FX;
    property Y: TBigInteger read FY;
    property Z: TBigInteger read FZ;
  end;

  TP256Curve = record
  private
    const
      PrimeHex      = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff';
      OrderHex      = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';
      CoefficientB  = '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b';
      GeneratorXHex = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296';
      GeneratorYHex = '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
      ScalarBits    = 256;

    var
      FField: TPrimeField;
      FOrder: TBigInteger;
      FB: TBigInteger;
      FThree: TBigInteger;
      FGenerator: TP256Point;

    function AddDistinct(const Left, Right: TP256Point): TP256Point;
    function SelectTerm(const HasFirst, HasSecond: Boolean;
                        const First, Second, Both: TP256Point): TP256Point;

  public
    class function Create: TP256Curve; static;

    function IsOnCurve(const X, Y: TBigInteger): Boolean;
    function AffinePoint(const X, Y: TBigInteger): TP256Point;
    function MultiplyTwo(const GeneratorScalar: TBigInteger;
                         const PointScalar: TBigInteger;
                         const Point: TP256Point): TP256Point;
    function Add(const Left, Right: TP256Point): TP256Point;
    function Double(const Point: TP256Point): TP256Point;
    function TryGetAffineX(const Point: TP256Point; out X: TBigInteger): Boolean;

    property Order: TBigInteger read FOrder;
    property Generator: TP256Point read FGenerator;
  end;

implementation

class function TP256Point.Create(const X, Y, Z: TBigInteger): TP256Point;
begin
  Result.FX := X;
  Result.FY := Y;
  Result.FZ := Z;
end;

class function TP256Point.Infinity: TP256Point;
begin
  Result := Create(TBigInteger.One, TBigInteger.One, TBigInteger.Zero);
end;

function TP256Point.IsInfinity: Boolean;
begin
  Result := FZ.IsZero;
end;

class function TP256Curve.Create: TP256Curve;
begin
  const Prime      = TBigInteger.FromHex(PrimeHex);
  const GeneratorX = TBigInteger.FromHex(GeneratorXHex);
  const GeneratorY = TBigInteger.FromHex(GeneratorYHex);

  Result.FField     := TPrimeField.Create(Prime);
  Result.FOrder     := TBigInteger.FromHex(OrderHex);
  Result.FB         := TBigInteger.FromHex(CoefficientB);
  Result.FThree     := TBigInteger.FromUInt64(3);
  Result.FGenerator := TP256Point.Create(GeneratorX, GeneratorY, TBigInteger.One);
end;

function TP256Curve.IsOnCurve(const X, Y: TBigInteger): Boolean;
begin
  const CoordinatesInField = (FField.Contains(X) and FField.Contains(Y));
  if not CoordinatesInField then
    Exit(False);

  const LeftSide  = FField.Square(Y);
  const XSquared  = FField.Square(X);
  const XCubed    = FField.Multiply(XSquared, X);
  const ThreeX    = FField.Multiply(FThree, X);
  const Reduced   = FField.Subtract(XCubed, ThreeX);
  const RightSide = FField.Add(Reduced, FB);

  Result := (LeftSide = RightSide);
end;

function TP256Curve.AffinePoint(const X, Y: TBigInteger): TP256Point;
begin
  Result := TP256Point.Create(X, Y, TBigInteger.One);
end;

function TP256Curve.MultiplyTwo(const GeneratorScalar: TBigInteger;
                                const PointScalar: TBigInteger;
                                const Point: TP256Point): TP256Point;
begin
  const Both = Add(FGenerator, Point);

  Result := TP256Point.Infinity;
  for var BitIndex := ScalarBits - 1 downto 0 do
  begin
    const HasGenerator = GeneratorScalar.TestBit(BitIndex);
    const HasPoint     = PointScalar.TestBit(BitIndex);
    const Term         = SelectTerm(HasGenerator, HasPoint, FGenerator, Point, Both);

    Result := Double(Result);
    Result := Add(Result, Term);
  end;
end;

function TP256Curve.SelectTerm(const HasFirst, HasSecond: Boolean;
                               const First, Second, Both: TP256Point): TP256Point;
begin
  if HasFirst and HasSecond then
    Exit(Both);
  if HasFirst then
    Exit(First);
  if HasSecond then
    Exit(Second);

  Result := TP256Point.Infinity;
end;

function TP256Curve.Add(const Left, Right: TP256Point): TP256Point;
begin
  if Left.IsInfinity then
    Exit(Right);
  if Right.IsInfinity then
    Exit(Left);

  Result := AddDistinct(Left, Right);
end;

function TP256Curve.AddDistinct(const Left, Right: TP256Point): TP256Point;
begin
  const LeftZSqr   = FField.Square(Left.Z);
  const RightZSqr  = FField.Square(Right.Z);
  const LeftU      = FField.Multiply(Left.X, RightZSqr);
  const RightU     = FField.Multiply(Right.X, LeftZSqr);
  const RightZCube = FField.Multiply(Right.Z, RightZSqr);
  const LeftZCube  = FField.Multiply(Left.Z, LeftZSqr);
  const LeftS      = FField.Multiply(Left.Y, RightZCube);
  const RightS     = FField.Multiply(Right.Y, LeftZCube);

  const SameX = (LeftU = RightU);
  const SameY = (LeftS = RightS);
  if SameX and SameY then
  begin
    Result := Double(Left);
    Exit;
  end;
  if SameX then
    Exit(TP256Point.Infinity);

  const DeltaX     = FField.Subtract(RightU, LeftU);
  const DeltaY     = FField.Subtract(RightS, LeftS);
  const DeltaXSqr  = FField.Square(DeltaX);
  const DeltaXCube = FField.Multiply(DeltaX, DeltaXSqr);
  const Shared     = FField.Multiply(LeftU, DeltaXSqr);

  const DeltaYSqr  = FField.Square(DeltaY);
  const TwoShared  = FField.Double(Shared);
  const WithoutH   = FField.Subtract(DeltaYSqr, DeltaXCube);
  const ResultX    = FField.Subtract(WithoutH, TwoShared);

  const SharedMinusX = FField.Subtract(Shared, ResultX);
  const Slope        = FField.Multiply(DeltaY, SharedMinusX);
  const Correction   = FField.Multiply(LeftS, DeltaXCube);
  const ResultY      = FField.Subtract(Slope, Correction);

  const ZProduct = FField.Multiply(Left.Z, Right.Z);
  const ResultZ  = FField.Multiply(ZProduct, DeltaX);

  Result := TP256Point.Create(ResultX, ResultY, ResultZ);
end;

function TP256Curve.Double(const Point: TP256Point): TP256Point;
begin
  const HasNoDouble = (Point.IsInfinity or Point.Y.IsZero);
  if HasNoDouble then
    Exit(TP256Point.Infinity);

  const Delta      = FField.Square(Point.Z);
  const Gamma      = FField.Square(Point.Y);
  const Beta       = FField.Multiply(Point.X, Gamma);
  const XMinus     = FField.Subtract(Point.X, Delta);
  const XPlus      = FField.Add(Point.X, Delta);
  const Product    = FField.Multiply(XMinus, XPlus);
  const Alpha      = FField.Multiply(FThree, Product);

  const TwoBeta    = FField.Double(Beta);
  const FourBeta   = FField.Double(TwoBeta);
  const EightBeta  = FField.Double(FourBeta);
  const AlphaSqr   = FField.Square(Alpha);
  const ResultX    = FField.Subtract(AlphaSqr, EightBeta);

  const YPlusZ     = FField.Add(Point.Y, Point.Z);
  const YPlusZSqr  = FField.Square(YPlusZ);
  const WithoutG   = FField.Subtract(YPlusZSqr, Gamma);
  const ResultZ    = FField.Subtract(WithoutG, Delta);

  const GammaSqr   = FField.Square(Gamma);
  const TwoGamma   = FField.Double(GammaSqr);
  const FourGamma  = FField.Double(TwoGamma);
  const EightGamma = FField.Double(FourGamma);
  const BetaMinusX = FField.Subtract(FourBeta, ResultX);
  const Slope      = FField.Multiply(Alpha, BetaMinusX);
  const ResultY    = FField.Subtract(Slope, EightGamma);

  Result := TP256Point.Create(ResultX, ResultY, ResultZ);
end;

function TP256Curve.TryGetAffineX(const Point: TP256Point; out X: TBigInteger): Boolean;
begin
  X := TBigInteger.Zero;
  if Point.IsInfinity then
    Exit(False);

  const ZInverse    = FField.Invert(Point.Z);
  const ZInverseSqr = FField.Square(ZInverse);

  X      := FField.Multiply(Point.X, ZInverseSqr);
  Result := True;
end;

end.
