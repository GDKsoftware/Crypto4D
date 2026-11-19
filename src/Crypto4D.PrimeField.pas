unit Crypto4D.PrimeField;

interface

uses
  Crypto4D.BigInteger;

type
  /// <summary>
  ///   Arithmetic modulo a prime. Add, Subtract, Negate and Double expect operands that are already below the
  ///   modulus; Multiply, Square and Power accept any operand and reduce the result.
  /// </summary>
  TPrimeField = record
  private
    FModulus: TBigInteger;

  public
    /// <summary>
    ///   Creates the field of integers modulo a prime.
    /// </summary>
    /// <param name="Modulus">The prime. It is not checked for primality.</param>
    class function Create(const Modulus: TBigInteger): TPrimeField; static;

    /// <summary>
    ///   True when Value is below the modulus.
    /// </summary>
    function Contains(const Value: TBigInteger): Boolean;

    /// <summary>
    ///   Returns Left + Right mod the modulus. Both operands must be below the modulus.
    /// </summary>
    function Add(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns Left - Right mod the modulus. Both operands must be below the modulus.
    /// </summary>
    function Subtract(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns the modulus minus Value, or zero for zero. Value must be below the modulus.
    /// </summary>
    function Negate(const Value: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns 2 * Value mod the modulus. Value must be below the modulus.
    /// </summary>
    function Double(const Value: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns Left * Right mod the modulus.
    /// </summary>
    function Multiply(const Left, Right: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns Value * Value mod the modulus.
    /// </summary>
    function Square(const Value: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns Base to the power Exponent, mod the modulus.
    /// </summary>
    function Power(const Base, Exponent: TBigInteger): TBigInteger;

    /// <summary>
    ///   Returns the inverse of Value mod the modulus.
    /// </summary>
    /// <exception cref="ECrypto4DArithmeticError">Value is zero or another multiple of the modulus.</exception>
    function Invert(const Value: TBigInteger): TBigInteger;

    /// <summary>
    ///   The prime that defines the field.
    /// </summary>
    property Modulus: TBigInteger read FModulus;
  end;

implementation

class function TPrimeField.Create(const Modulus: TBigInteger): TPrimeField;
begin
  Result.FModulus := Modulus;
end;

function TPrimeField.Contains(const Value: TBigInteger): Boolean;
begin
  Result := (Value < FModulus);
end;

function TPrimeField.Add(const Left, Right: TBigInteger): TBigInteger;
begin
  Result := Left + Right;

  const NeedsReduction = (Result >= FModulus);
  if NeedsReduction then
    Result := Result - FModulus;
end;

function TPrimeField.Subtract(const Left, Right: TBigInteger): TBigInteger;
begin
  const StaysPositive = (Left >= Right);
  if StaysPositive then
  begin
    Result := Left - Right;
    Exit;
  end;

  const Raised = Left + FModulus;
  Result := Raised - Right;
end;

function TPrimeField.Negate(const Value: TBigInteger): TBigInteger;
begin
  if Value.IsZero then
    Exit(Value);

  Result := FModulus - Value;
end;

function TPrimeField.Double(const Value: TBigInteger): TBigInteger;
begin
  Result := Add(Value, Value);
end;

function TPrimeField.Multiply(const Left, Right: TBigInteger): TBigInteger;
begin
  const Product = Left * Right;
  Result := Product mod FModulus;
end;

function TPrimeField.Square(const Value: TBigInteger): TBigInteger;
begin
  Result := Multiply(Value, Value);
end;

function TPrimeField.Power(const Base, Exponent: TBigInteger): TBigInteger;
begin
  Result := Base.ModPow(Exponent, FModulus);
end;

function TPrimeField.Invert(const Value: TBigInteger): TBigInteger;
begin
  Result := Value.ModInverse(FModulus);
end;

end.
