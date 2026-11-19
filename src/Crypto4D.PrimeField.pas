unit Crypto4D.PrimeField;

interface

uses
  Crypto4D.BigInteger;

type
  TPrimeField = record
  private
    FModulus: TBigInteger;

  public
    class function Create(const Modulus: TBigInteger): TPrimeField; static;

    function Contains(const Value: TBigInteger): Boolean;
    function Add(const Left, Right: TBigInteger): TBigInteger;
    function Subtract(const Left, Right: TBigInteger): TBigInteger;
    function Negate(const Value: TBigInteger): TBigInteger;
    function Double(const Value: TBigInteger): TBigInteger;
    function Multiply(const Left, Right: TBigInteger): TBigInteger;
    function Square(const Value: TBigInteger): TBigInteger;
    function Power(const Base, Exponent: TBigInteger): TBigInteger;
    function Invert(const Value: TBigInteger): TBigInteger;

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
