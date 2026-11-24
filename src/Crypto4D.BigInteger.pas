unit Crypto4D.BigInteger;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   Non-negative integer of any size. A value never changes: every operation returns a new value. A variable
  ///   that was never assigned is zero. The arithmetic does not run in constant time, so do not use it for secret
  ///   values.
  /// </summary>
  TBigInteger = record
  private
    const
      LimbBits          = 32;
      LimbBytes         = 4;
      BitsPerByte       = 8;
      LimbMask: UInt64  = $FFFFFFFF;
      LimbBase: UInt64  = $100000000;
      SignedBase: Int64 = $100000000;
      HexDigitsPerByte  = 2;
      HexDigits         = '0123456789abcdef';

    var
      FLimbs: TArray<UInt32>;

    class function FromLimbs(const Limbs: TArray<UInt32>): TBigInteger; static;
    class function CompareLimbs(const Left, Right: TArray<UInt32>): Integer; static;
    class function AddLimbs(const Left, Right: TArray<UInt32>): TArray<UInt32>; static;
    class function SubtractLimbs(const Left, Right: TArray<UInt32>): TArray<UInt32>; static;
    class function MultiplyLimbs(const Left, Right: TArray<UInt32>): TArray<UInt32>; static;
    class function LimbBitLength(const Limb: UInt32): Integer; static;
    class function ShiftLeftToLength(const Limbs: TArray<UInt32>;
                                     const BitCount: Integer;
                                     const ResultLength: NativeInt): TArray<UInt32>; static;
    class function ShiftRightLimbs(const Limbs: TArray<UInt32>; const BitCount: Integer): TArray<UInt32>; static;
    class procedure DivideBySingleLimb(const Dividend: TArray<UInt32>;
                                       const Divisor: UInt32;
                                       out Quotient: TBigInteger;
                                       out Remainder: TBigInteger); static;
    class procedure DivideByMultipleLimbs(const Dividend, Divisor: TArray<UInt32>;
                                          out Quotient: TBigInteger;
                                          out Remainder: TBigInteger); static;
    class function EstimateQuotientDigit(const Remainder, Divisor: TArray<UInt32>; const Position: NativeInt): UInt64; static;
    class function SubtractProduct(var Remainder: TArray<UInt32>;
                                   const Divisor: TArray<UInt32>;
                                   const QuotientDigit: UInt64;
                                   const Position: NativeInt): Boolean; static;
    class procedure AddBack(var Remainder: TArray<UInt32>; const Divisor: TArray<UInt32>; const Position: NativeInt); static;
    class function HexDigitValue(const Digit: Char): Byte; static;
    class procedure GuardModulus(const Modulus: TBigInteger); static;

  public
    /// <summary>
    ///   Returns the value 0.
    /// </summary>
    class function Zero: TBigInteger; static;

    /// <summary>
    ///   Returns the value 1.
    /// </summary>
    class function One: TBigInteger; static;

    /// <summary>
    ///   Converts an unsigned 64 bit integer.
    /// </summary>
    /// <param name="Value">Value to convert.</param>
    class function FromUInt64(const Value: UInt64): TBigInteger; static;

    /// <summary>
    ///   Reads an unsigned integer from big-endian bytes.
    /// </summary>
    /// <param name="BigEndianBytes">Most significant byte first, any length. Leading zero bytes are ignored and an
    ///   empty array is zero.</param>
    class function FromBytes(const BigEndianBytes: TBytes): TBigInteger; static;

    /// <summary>
    ///   Reads an unsigned integer from hexadecimal text.
    /// </summary>
    /// <param name="Hex">Hexadecimal digits in upper or lower case, without prefix or separators. An odd number of
    ///   digits is allowed and an empty string is zero.</param>
    /// <exception cref="ECrypto4DArgumentError">Hex holds a character that is not a hexadecimal digit.</exception>
    class function FromHex(const Hex: string): TBigInteger; static;

    /// <summary>
    ///   Compares two values.
    /// </summary>
    /// <param name="Left">First value.</param>
    /// <param name="Right">Second value.</param>
    /// <returns>-1 when Left is smaller than Right, 0 when they are equal and 1 when Left is larger.</returns>
    class function Compare(const Left, Right: TBigInteger): Integer; static;

    /// <summary>
    ///   Divides and returns quotient and remainder in one call.
    /// </summary>
    /// <param name="Dividend">Value to divide.</param>
    /// <param name="Divisor">Value to divide by; must not be zero.</param>
    /// <param name="Quotient">Receives Dividend div Divisor.</param>
    /// <param name="Remainder">Receives Dividend mod Divisor.</param>
    /// <exception cref="ECrypto4DArithmeticError">Divisor is zero.</exception>
    class procedure DivMod(const Dividend, Divisor: TBigInteger; out Quotient, Remainder: TBigInteger); static;

    /// <summary>
    ///   Adds two values.
    /// </summary>
    class operator Add(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Subtracts Right from Left.
    /// </summary>
    /// <exception cref="ECrypto4DArithmeticError">Right is larger than Left, so the result would be
    ///   negative.</exception>
    class operator Subtract(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Multiplies two values.
    /// </summary>
    class operator Multiply(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Divides Left by Right and drops the remainder.
    /// </summary>
    /// <exception cref="ECrypto4DArithmeticError">Right is zero.</exception>
    class operator IntDivide(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns the remainder of Left divided by Right.
    /// </summary>
    /// <exception cref="ECrypto4DArithmeticError">Right is zero.</exception>
    class operator Modulus(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Shifts a value left, which multiplies it by 2 to the power BitCount.
    /// </summary>
    /// <param name="Value">Value to shift.</param>
    /// <param name="BitCount">Number of bits, zero or more.</param>
    /// <exception cref="ECrypto4DArgumentError">BitCount is negative.</exception>
    class operator LeftShift(const Value: TBigInteger; const BitCount: Integer): TBigInteger;

    /// <summary>
    ///   Shifts a value right, which divides it by 2 to the power BitCount and drops the remainder.
    /// </summary>
    /// <param name="Value">Value to shift.</param>
    /// <param name="BitCount">Number of bits, zero or more. A count at or beyond the bit length gives zero.</param>
    /// <exception cref="ECrypto4DArgumentError">BitCount is negative.</exception>
    class operator RightShift(const Value: TBigInteger; const BitCount: Integer): TBigInteger;

    /// <summary>
    ///   True when both values are equal.
    /// </summary>
    class operator Equal(const Left, Right: TBigInteger): Boolean;

    /// <summary>
    ///   True when the values differ.
    /// </summary>
    class operator NotEqual(const Left, Right: TBigInteger): Boolean;

    /// <summary>
    ///   True when Left is smaller than Right.
    /// </summary>
    class operator LessThan(const Left, Right: TBigInteger): Boolean;

    /// <summary>
    ///   True when Left is smaller than or equal to Right.
    /// </summary>
    class operator LessThanOrEqual(const Left, Right: TBigInteger): Boolean;

    /// <summary>
    ///   True when Left is larger than Right.
    /// </summary>
    class operator GreaterThan(const Left, Right: TBigInteger): Boolean;

    /// <summary>
    ///   True when Left is larger than or equal to Right.
    /// </summary>
    class operator GreaterThanOrEqual(const Left, Right: TBigInteger): Boolean;

    /// <summary>
    ///   True when the value is 0.
    /// </summary>
    function IsZero: Boolean;

    /// <summary>
    ///   True when the value is 1.
    /// </summary>
    function IsOne: Boolean;

    /// <summary>
    ///   True when the lowest bit is set.
    /// </summary>
    function IsOdd: Boolean;

    /// <summary>
    ///   Returns the number of bits needed to write the value. Zero has a bit length of 0.
    /// </summary>
    function BitLength: Int64;

    /// <summary>
    ///   Returns the number of bytes needed to write the value. Zero has a byte length of 0.
    /// </summary>
    function ByteLength: NativeInt;

    /// <summary>
    ///   Tells whether one bit of the value is set.
    /// </summary>
    /// <param name="BitIndex">Bit number, where bit 0 is the least significant bit.</param>
    /// <returns>True when the bit is set. False for an index beyond the bit length.</returns>
    /// <exception cref="ECrypto4DArgumentError">BitIndex is negative.</exception>
    function TestBit(const BitIndex: Int64): Boolean;

    /// <summary>
    ///   Writes the value as big-endian bytes without leading zero bytes.
    /// </summary>
    /// <returns>The shortest big-endian encoding. Zero gives a single zero byte.</returns>
    function ToBytes: TBytes;

    /// <summary>
    ///   Writes the value as big-endian bytes, padded with zero bytes on the left to a fixed length.
    /// </summary>
    /// <param name="ByteCount">Length of the result in bytes.</param>
    /// <returns>ByteCount bytes, most significant byte first.</returns>
    /// <exception cref="ECrypto4DArgumentError">The value needs more than ByteCount bytes.</exception>
    function ToFixedBytes(const ByteCount: NativeInt): TBytes;

    /// <summary>
    ///   Writes the value as lower case hexadecimal text.
    /// </summary>
    /// <returns>Two digits for every byte of ToBytes, so the number of digits is even. Zero gives 00.</returns>
    function ToHex: string;

    /// <summary>
    ///   Raises the value to a power, reduced by a modulus.
    /// </summary>
    /// <param name="Exponent">Power to raise to; zero or more.</param>
    /// <param name="Modulus">Modulus; must not be zero.</param>
    /// <returns>The value to the power Exponent, mod Modulus. The result is 0 when Modulus is 1.</returns>
    /// <exception cref="ECrypto4DArithmeticError">Modulus is zero.</exception>
    function ModPow(const Exponent, Modulus: TBigInteger): TBigInteger;

    /// <summary>
    ///   Looks for the inverse of the value for a modulus.
    /// </summary>
    /// <param name="Modulus">Modulus; must not be zero.</param>
    /// <param name="Inverse">Receives the number below Modulus that gives 1 when multiplied by the value, mod
    ///   Modulus. Zero when there is no inverse.</param>
    /// <returns>True when the inverse exists, which is when the value and Modulus share no factor. False
    ///   otherwise.</returns>
    /// <exception cref="ECrypto4DArithmeticError">Modulus is zero.</exception>
    function TryModInverse(const Modulus: TBigInteger; out Inverse: TBigInteger): Boolean;

    /// <summary>
    ///   Returns the inverse of the value for a modulus.
    /// </summary>
    /// <param name="Modulus">Modulus; must not be zero.</param>
    /// <returns>The number below Modulus that gives 1 when multiplied by the value, mod Modulus.</returns>
    /// <exception cref="ECrypto4DArithmeticError">Modulus is zero, or the value has no inverse because it shares a
    ///   factor with Modulus.</exception>
    function ModInverse(const Modulus: TBigInteger): TBigInteger;
  end;

implementation

uses
  Crypto4D.Errors;

resourcestring
  DivisionByZero        = 'Division by zero';
  NegativeDifference    = 'Subtraction would give a negative result; TBigInteger holds non-negative values only';
  NegativeShift         = 'Shift count %d is negative';
  NegativeBitIndex      = 'Bit index %d is negative';
  InvalidHexDigit       = 'Invalid hexadecimal digit "%s"';
  ValueDoesNotFit       = 'Value of %d bytes does not fit in %d bytes';
  ModulusIsZero         = 'Modulus is zero';
  ValueIsNotInvertible  = 'Value has no inverse for the given modulus';

class function TBigInteger.Zero: TBigInteger;
begin
  Result.FLimbs := nil;
end;

class function TBigInteger.One: TBigInteger;
begin
  Result.FLimbs := [1];
end;

class function TBigInteger.FromUInt64(const Value: UInt64): TBigInteger;
begin
  const LowLimb  = UInt32(Value and LimbMask);
  const HighLimb = UInt32(Value shr LimbBits);

  Result := FromLimbs([LowLimb, HighLimb]);
end;

class function TBigInteger.FromBytes(const BigEndianBytes: TBytes): TBigInteger;
begin
  const ByteCount = Length(BigEndianBytes);
  const LimbCount = (ByteCount + LimbBytes - 1) div LimbBytes;
  var Limbs: TArray<UInt32>;
  SetLength(Limbs, LimbCount);

  for var ByteIndex := 0 to ByteCount - 1 do
  begin
    const ByteValue: UInt32 = BigEndianBytes[ByteCount - 1 - ByteIndex];
    const LimbIndex         = ByteIndex div LimbBytes;
    const Shift             = (ByteIndex mod LimbBytes) * BitsPerByte;
    Limbs[LimbIndex] := Limbs[LimbIndex] or (ByteValue shl Shift);
  end;

  Result := FromLimbs(Limbs);
end;

class function TBigInteger.FromHex(const Hex: string): TBigInteger;
begin
  const DigitCount = Length(Hex);
  const ByteCount  = (DigitCount + 1) div HexDigitsPerByte;
  var Bytes: TBytes;
  SetLength(Bytes, ByteCount);

  for var DigitIndex := 0 to DigitCount - 1 do
  begin
    const Digit                = Hex[DigitCount - DigitIndex];
    const Value                = HexDigitValue(Digit);
    const ByteIndex            = ByteCount - 1 - (DigitIndex div HexDigitsPerByte);
    const IsHighNibble         = Odd(DigitIndex);
    const ShiftedValue: UInt32 = Value;
    if IsHighNibble then
      Bytes[ByteIndex] := Bytes[ByteIndex] or Byte(ShiftedValue shl 4)
    else
      Bytes[ByteIndex] := Bytes[ByteIndex] or Value;
  end;

  Result := FromBytes(Bytes);
end;

class function TBigInteger.HexDigitValue(const Digit: Char): Byte;
begin
  case Digit of
    '0'..'9' : Result := Byte(Ord(Digit) - Ord('0'));
    'a'..'f' : Result := Byte(Ord(Digit) - Ord('a') + 10);
    'A'..'F' : Result := Byte(Ord(Digit) - Ord('A') + 10);
  else
    raise ECrypto4DArgumentError.CreateFmt(InvalidHexDigit, [Digit]);
  end;
end;

class function TBigInteger.Compare(const Left, Right: TBigInteger): Integer;
begin
  Result := CompareLimbs(Left.FLimbs, Right.FLimbs);
end;

class procedure TBigInteger.DivMod(const Dividend, Divisor: TBigInteger; out Quotient, Remainder: TBigInteger);
begin
  if Divisor.IsZero then
    raise ECrypto4DArithmeticError.Create(DivisionByZero);

  const DividendIsSmaller = (CompareLimbs(Dividend.FLimbs, Divisor.FLimbs) < 0);
  if DividendIsSmaller then
  begin
    Quotient  := Zero;
    Remainder := Dividend;
    Exit;
  end;

  const DivisorHasSingleLimb = (Length(Divisor.FLimbs) = 1);
  if DivisorHasSingleLimb then
    DivideBySingleLimb(Dividend.FLimbs, Divisor.FLimbs[0], Quotient, Remainder)
  else
    DivideByMultipleLimbs(Dividend.FLimbs, Divisor.FLimbs, Quotient, Remainder);
end;

class operator TBigInteger.Add(const Left, Right: TBigInteger): TBigInteger;
begin
  const Sum = AddLimbs(Left.FLimbs, Right.FLimbs);
  Result := FromLimbs(Sum);
end;

class operator TBigInteger.Subtract(const Left, Right: TBigInteger): TBigInteger;
begin
  const ResultIsNegative = (CompareLimbs(Left.FLimbs, Right.FLimbs) < 0);
  if ResultIsNegative then
    raise ECrypto4DArithmeticError.Create(NegativeDifference);

  const Difference = SubtractLimbs(Left.FLimbs, Right.FLimbs);
  Result := FromLimbs(Difference);
end;

class operator TBigInteger.Multiply(const Left, Right: TBigInteger): TBigInteger;
begin
  const Product = MultiplyLimbs(Left.FLimbs, Right.FLimbs);
  Result := FromLimbs(Product);
end;

class operator TBigInteger.IntDivide(const Left, Right: TBigInteger): TBigInteger;
begin
  var Remainder: TBigInteger;
  DivMod(Left, Right, Result, Remainder);
end;

class operator TBigInteger.Modulus(const Left, Right: TBigInteger): TBigInteger;
begin
  var Quotient: TBigInteger;
  DivMod(Left, Right, Quotient, Result);
end;

class operator TBigInteger.LeftShift(const Value: TBigInteger; const BitCount: Integer): TBigInteger;
begin
  const IsNegativeCount = (BitCount < 0);
  if IsNegativeCount then
    raise ECrypto4DArgumentError.CreateFmt(NegativeShift, [BitCount]);

  if Value.IsZero then
    Exit(Zero);

  const ResultLength = Length(Value.FLimbs) + (BitCount div LimbBits) + 1;
  const Shifted = ShiftLeftToLength(Value.FLimbs, BitCount, ResultLength);
  Result := FromLimbs(Shifted);
end;

class operator TBigInteger.RightShift(const Value: TBigInteger; const BitCount: Integer): TBigInteger;
begin
  const IsNegativeCount = (BitCount < 0);
  if IsNegativeCount then
    raise ECrypto4DArgumentError.CreateFmt(NegativeShift, [BitCount]);

  const Shifted = ShiftRightLimbs(Value.FLimbs, BitCount);
  Result := FromLimbs(Shifted);
end;

class operator TBigInteger.Equal(const Left, Right: TBigInteger): Boolean;
begin
  Result := (CompareLimbs(Left.FLimbs, Right.FLimbs) = 0);
end;

class operator TBigInteger.NotEqual(const Left, Right: TBigInteger): Boolean;
begin
  Result := (CompareLimbs(Left.FLimbs, Right.FLimbs) <> 0);
end;

class operator TBigInteger.LessThan(const Left, Right: TBigInteger): Boolean;
begin
  Result := (CompareLimbs(Left.FLimbs, Right.FLimbs) < 0);
end;

class operator TBigInteger.LessThanOrEqual(const Left, Right: TBigInteger): Boolean;
begin
  Result := (CompareLimbs(Left.FLimbs, Right.FLimbs) <= 0);
end;

class operator TBigInteger.GreaterThan(const Left, Right: TBigInteger): Boolean;
begin
  Result := (CompareLimbs(Left.FLimbs, Right.FLimbs) > 0);
end;

class operator TBigInteger.GreaterThanOrEqual(const Left, Right: TBigInteger): Boolean;
begin
  Result := (CompareLimbs(Left.FLimbs, Right.FLimbs) >= 0);
end;

function TBigInteger.IsZero: Boolean;
begin
  Result := (Length(FLimbs) = 0);
end;

function TBigInteger.IsOne: Boolean;
begin
  Result := (Length(FLimbs) = 1) and (FLimbs[0] = 1);
end;

function TBigInteger.IsOdd: Boolean;
begin
  Result := (Length(FLimbs) > 0) and Odd(FLimbs[0]);
end;

function TBigInteger.BitLength: Int64;
begin
  if IsZero then
    Exit(0);

  const TopIndex: Int64 = High(FLimbs);
  const TopBits         = LimbBitLength(FLimbs[TopIndex]);
  Result := TopIndex * LimbBits + TopBits;
end;

function TBigInteger.ByteLength: NativeInt;
begin
  if IsZero then
    Exit(0);

  const TopIndex = High(FLimbs);
  const TopBits  = LimbBitLength(FLimbs[TopIndex]);
  const TopBytes = (TopBits + BitsPerByte - 1) div BitsPerByte;
  Result := TopIndex * LimbBytes + TopBytes;
end;

function TBigInteger.TestBit(const BitIndex: Int64): Boolean;
begin
  const IsNegativeIndex = (BitIndex < 0);
  if IsNegativeIndex then
    raise ECrypto4DArgumentError.CreateFmt(NegativeBitIndex, [BitIndex]);

  const LimbIndex     = BitIndex div LimbBits;
  const IsBeyondValue = (LimbIndex >= Length(FLimbs));
  if IsBeyondValue then
    Exit(False);

  const ShiftedLimb = FLimbs[LimbIndex] shr (BitIndex mod LimbBits);
  Result := Odd(ShiftedLimb);
end;

function TBigInteger.ToBytes: TBytes;
begin
  if IsZero then
  begin
    Result := TBytes.Create(0);
    Exit;
  end;

  const RequiredBytes = ByteLength;
  Result := ToFixedBytes(RequiredBytes);
end;

function TBigInteger.ToFixedBytes(const ByteCount: NativeInt): TBytes;
begin
  const RequiredBytes = ByteLength;
  const DoesNotFit    = (RequiredBytes > ByteCount);
  if DoesNotFit then
    raise ECrypto4DArgumentError.CreateFmt(ValueDoesNotFit, [RequiredBytes, ByteCount]);

  SetLength(Result, ByteCount);
  for var ByteIndex := 0 to RequiredBytes - 1 do
  begin
    const Limb        = FLimbs[ByteIndex div LimbBytes];
    const Shift       = (ByteIndex mod LimbBytes) * BitsPerByte;
    const ShiftedLimb = Limb shr Shift;
    Result[ByteCount - 1 - ByteIndex] := Byte(ShiftedLimb and $FF);
  end;
end;

function TBigInteger.ToHex: string;
begin
  const Bytes = ToBytes;
  SetLength(Result, Length(Bytes) * HexDigitsPerByte);

  for var ByteIndex := 0 to High(Bytes) do
  begin
    const Value = Bytes[ByteIndex];
    Result[ByteIndex * HexDigitsPerByte + 1] := HexDigits[(Value shr 4) + 1];
    Result[ByteIndex * HexDigitsPerByte + 2] := HexDigits[(Value and $0F) + 1];
  end;
end;

function TBigInteger.ModPow(const Exponent, Modulus: TBigInteger): TBigInteger;
begin
  GuardModulus(Modulus);
  if Modulus.IsOne then
    Exit(Zero);

  const Base = Self mod Modulus;
  Result := One;
  for var BitIndex := Exponent.BitLength - 1 downto 0 do
  begin
    Result := (Result * Result) mod Modulus;
    const MultipliesByBase = Exponent.TestBit(BitIndex);
    if MultipliesByBase then
      Result := (Result * Base) mod Modulus;
  end;
end;

function TBigInteger.ModInverse(const Modulus: TBigInteger): TBigInteger;
begin
  const IsInvertible = TryModInverse(Modulus, Result);
  if not IsInvertible then
    raise ECrypto4DArithmeticError.Create(ValueIsNotInvertible);
end;

function TBigInteger.TryModInverse(const Modulus: TBigInteger; out Inverse: TBigInteger): Boolean;
begin
  GuardModulus(Modulus);

  var PreviousRemainder   := Modulus;
  var CurrentRemainder    := Self mod Modulus;
  var PreviousCoefficient := Zero;
  var CurrentCoefficient  := One mod Modulus;

  while not CurrentRemainder.IsZero do
  begin
    var Quotient: TBigInteger;
    var NextRemainder: TBigInteger;
    DivMod(PreviousRemainder, CurrentRemainder, Quotient, NextRemainder);
    const Product         = (Quotient * CurrentCoefficient) mod Modulus;
    const NextCoefficient = (PreviousCoefficient + Modulus - Product) mod Modulus;

    PreviousRemainder   := CurrentRemainder;
    CurrentRemainder    := NextRemainder;
    PreviousCoefficient := CurrentCoefficient;
    CurrentCoefficient  := NextCoefficient;
  end;

  Result := PreviousRemainder.IsOne;
  if Result then
    Inverse := PreviousCoefficient
  else
    Inverse := Zero;
end;

class procedure TBigInteger.GuardModulus(const Modulus: TBigInteger);
begin
  if Modulus.IsZero then
    raise ECrypto4DArithmeticError.Create(ModulusIsZero);
end;

class function TBigInteger.FromLimbs(const Limbs: TArray<UInt32>): TBigInteger;
begin
  var SignificantCount := Length(Limbs);
  while (SignificantCount > 0) and (Limbs[SignificantCount - 1] = 0) do
  begin
    Dec(SignificantCount);
  end;

  Result.FLimbs := Copy(Limbs, 0, SignificantCount);
end;

class function TBigInteger.CompareLimbs(const Left, Right: TArray<UInt32>): Integer;
begin
  const LeftLength  = Length(Left);
  const RightLength = Length(Right);
  const LeftIsShorter = (LeftLength < RightLength);
  const LeftIsLonger  = (LeftLength > RightLength);
  if LeftIsShorter then
    Exit(-1);
  if LeftIsLonger then
    Exit(1);

  for var Index := LeftLength - 1 downto 0 do
  begin
    const LeftIsSmaller = (Left[Index] < Right[Index]);
    const LeftIsLarger  = (Left[Index] > Right[Index]);
    if LeftIsSmaller then
      Exit(-1);
    if LeftIsLarger then
      Exit(1);
  end;

  Result := 0;
end;

class function TBigInteger.AddLimbs(const Left, Right: TArray<UInt32>): TArray<UInt32>;
begin
  const LeftIsLonger = (Length(Left) >= Length(Right));
  var Longer  := Right;
  var Shorter := Left;
  if LeftIsLonger then
  begin
    Longer  := Left;
    Shorter := Right;
  end;

  const LongerLength  = Length(Longer);
  const ShorterLength = Length(Shorter);
  SetLength(Result, LongerLength + 1);

  var Carry: UInt64 := 0;
  for var Index := 0 to LongerLength - 1 do
  begin
    var Sum: UInt64 := Carry + Longer[Index];
    const HasShorterLimb = (Index < ShorterLength);
    if HasShorterLimb then
      Sum := Sum + Shorter[Index];

    Result[Index] := UInt32(Sum and LimbMask);
    Carry         := Sum shr LimbBits;
  end;
  Result[LongerLength] := UInt32(Carry);
end;

class function TBigInteger.SubtractLimbs(const Left, Right: TArray<UInt32>): TArray<UInt32>;
begin
  const LeftLength  = Length(Left);
  const RightLength = Length(Right);
  SetLength(Result, LeftLength);

  var Borrow: Int64 := 0;
  for var Index := 0 to LeftLength - 1 do
  begin
    var Difference: Int64 := Int64(Left[Index]) - Borrow;
    const HasRightLimb = (Index < RightLength);
    if HasRightLimb then
      Difference := Difference - Int64(Right[Index]);

    Borrow := 0;
    const NeedsBorrow = (Difference < 0);
    if NeedsBorrow then
    begin
      Difference := Difference + SignedBase;
      Borrow     := 1;
    end;
    Result[Index] := UInt32(Difference);
  end;
end;

class function TBigInteger.MultiplyLimbs(const Left, Right: TArray<UInt32>): TArray<UInt32>;
begin
  const LeftLength  = Length(Left);
  const RightLength = Length(Right);
  const HasZeroFactor = (LeftLength = 0) or (RightLength = 0);
  if HasZeroFactor then
    Exit(nil);

  SetLength(Result, LeftLength + RightLength);
  for var LeftIndex := 0 to LeftLength - 1 do
  begin
    const LeftLimb: UInt64 = Left[LeftIndex];
    var Carry: UInt64 := 0;
    for var RightIndex := 0 to RightLength - 1 do
    begin
      const Position        = LeftIndex + RightIndex;
      const Product: UInt64 = LeftLimb * Right[RightIndex] + Result[Position] + Carry;
      Result[Position] := UInt32(Product and LimbMask);
      Carry            := Product shr LimbBits;
    end;
    Result[LeftIndex + RightLength] := UInt32(Carry);
  end;
end;

class function TBigInteger.LimbBitLength(const Limb: UInt32): Integer;
begin
  Result := 0;
  var Remaining := Limb;
  while Remaining <> 0 do
  begin
    Remaining := Remaining shr 1;
    Inc(Result);
  end;
end;

class function TBigInteger.ShiftLeftToLength(const Limbs: TArray<UInt32>;
                                             const BitCount: Integer;
                                             const ResultLength: NativeInt): TArray<UInt32>;
begin
  const LimbShift = BitCount div LimbBits;
  const BitShift  = BitCount mod LimbBits;
  SetLength(Result, ResultLength);

  var Carry: UInt64 := 0;
  for var Index := 0 to High(Limbs) do
  begin
    const Shifted: UInt64 = (UInt64(Limbs[Index]) shl BitShift) or Carry;
    Result[Index + LimbShift] := UInt32(Shifted and LimbMask);
    Carry                     := Shifted shr LimbBits;
  end;

  const CarryPosition = Length(Limbs) + LimbShift;
  const CarryFits     = (CarryPosition < ResultLength);
  if CarryFits then
    Result[CarryPosition] := UInt32(Carry);
end;

class function TBigInteger.ShiftRightLimbs(const Limbs: TArray<UInt32>; const BitCount: Integer): TArray<UInt32>;
begin
  const LimbShift    = BitCount div LimbBits;
  const BitShift     = BitCount mod LimbBits;
  const ResultLength = Length(Limbs) - LimbShift;
  const ShiftsAllOut = (ResultLength <= 0);
  if ShiftsAllOut then
    Exit(nil);

  SetLength(Result, ResultLength);
  for var Index := 0 to ResultLength - 1 do
  begin
    const SourceIndex = Index + LimbShift;
    var Combined: UInt64 := Limbs[SourceIndex];
    const HasHigherLimb = (SourceIndex + 1 < Length(Limbs));
    if HasHigherLimb then
      Combined := Combined or (UInt64(Limbs[SourceIndex + 1]) shl LimbBits);

    Result[Index] := UInt32((Combined shr BitShift) and LimbMask);
  end;
end;

class procedure TBigInteger.DivideBySingleLimb(const Dividend: TArray<UInt32>;
                                               const Divisor: UInt32;
                                               out Quotient: TBigInteger;
                                               out Remainder: TBigInteger);
begin
  var QuotientLimbs: TArray<UInt32>;
  SetLength(QuotientLimbs, Length(Dividend));

  var Carry: UInt64 := 0;
  for var Index := High(Dividend) downto 0 do
  begin
    const Numerator: UInt64 = (Carry shl LimbBits) or Dividend[Index];
    QuotientLimbs[Index] := UInt32(Numerator div Divisor);
    Carry                := Numerator mod Divisor;
  end;

  Quotient  := FromLimbs(QuotientLimbs);
  Remainder := FromUInt64(Carry);
end;

class procedure TBigInteger.DivideByMultipleLimbs(const Dividend, Divisor: TArray<UInt32>;
                                                  out Quotient: TBigInteger;
                                                  out Remainder: TBigInteger);
begin
  const DivisorLength  = Length(Divisor);
  const DividendLength = Length(Dividend);
  const QuotientLength = DividendLength - DivisorLength + 1;
  const Normalization  = LimbBits - LimbBitLength(Divisor[DivisorLength - 1]);

  const NormalizedDivisor = ShiftLeftToLength(Divisor, Normalization, DivisorLength);
  var Working := ShiftLeftToLength(Dividend, Normalization, DividendLength + 1);
  var QuotientLimbs: TArray<UInt32>;
  SetLength(QuotientLimbs, QuotientLength);

  for var Position := QuotientLength - 1 downto 0 do
  begin
    var QuotientDigit := EstimateQuotientDigit(Working, NormalizedDivisor, Position);
    const WentNegative = SubtractProduct(Working, NormalizedDivisor, QuotientDigit, Position);
    if WentNegative then
    begin
      AddBack(Working, NormalizedDivisor, Position);
      Dec(QuotientDigit);
    end;
    QuotientLimbs[Position] := UInt32(QuotientDigit);
  end;

  const NormalizedRemainder = Copy(Working, 0, DivisorLength);
  const RemainderLimbs      = ShiftRightLimbs(NormalizedRemainder, Normalization);
  Quotient  := FromLimbs(QuotientLimbs);
  Remainder := FromLimbs(RemainderLimbs);
end;

class function TBigInteger.EstimateQuotientDigit(const Remainder, Divisor: TArray<UInt32>; const Position: NativeInt): UInt64;
begin
  const DivisorLength       = Length(Divisor);
  const TopIndex            = Position + DivisorLength;
  const Numerator: UInt64   = (UInt64(Remainder[TopIndex]) shl LimbBits) or Remainder[TopIndex - 1];
  const DivisorTop: UInt64  = Divisor[DivisorLength - 1];
  const DivisorNext: UInt64 = Divisor[DivisorLength - 2];
  const NextDigit: UInt64   = Remainder[TopIndex - 2];

  Result := Numerator div DivisorTop;
  var EstimateRemainder: UInt64 := Numerator mod DivisorTop;

  while (Result >= LimbBase) or
        (Result * DivisorNext > ((EstimateRemainder shl LimbBits) or NextDigit)) do
  begin
    Dec(Result);
    EstimateRemainder := EstimateRemainder + DivisorTop;
    const RemainderLeftLimbRange = (EstimateRemainder >= LimbBase);
    if RemainderLeftLimbRange then
      Break;
  end;
end;

class function TBigInteger.SubtractProduct(var Remainder: TArray<UInt32>;
                                           const Divisor: TArray<UInt32>;
                                           const QuotientDigit: UInt64;
                                           const Position: NativeInt): Boolean;
begin
  const DivisorLength = Length(Divisor);
  var Carry: UInt64 := 0;
  var Borrow: Int64 := 0;

  for var Index := 0 to DivisorLength - 1 do
  begin
    const Product: UInt64 = QuotientDigit * Divisor[Index] + Carry;
    Carry := Product shr LimbBits;

    var Difference: Int64 := Int64(Remainder[Position + Index]) - Int64(Product and LimbMask) - Borrow;
    Borrow := 0;
    const NeedsBorrow = (Difference < 0);
    if NeedsBorrow then
    begin
      Difference := Difference + SignedBase;
      Borrow     := 1;
    end;
    Remainder[Position + Index] := UInt32(Difference);
  end;

  const TopIndex = Position + DivisorLength;
  var TopDifference: Int64 := Int64(Remainder[TopIndex]) - Int64(Carry) - Borrow;
  Result := (TopDifference < 0);
  if Result then
    TopDifference := TopDifference + SignedBase;
  Remainder[TopIndex] := UInt32(TopDifference);
end;

class procedure TBigInteger.AddBack(var Remainder: TArray<UInt32>; const Divisor: TArray<UInt32>; const Position: NativeInt);
begin
  const DivisorLength = Length(Divisor);
  var Carry: UInt64 := 0;

  for var Index := 0 to DivisorLength - 1 do
  begin
    const Sum: UInt64 = Carry + Remainder[Position + Index] + Divisor[Index];
    Remainder[Position + Index] := UInt32(Sum and LimbMask);
    Carry                       := Sum shr LimbBits;
  end;

  const TopIndex       = Position + DivisorLength;
  const TopSum: UInt64 = Carry + Remainder[TopIndex];
  Remainder[TopIndex] := UInt32(TopSum and LimbMask);
end;

end.
