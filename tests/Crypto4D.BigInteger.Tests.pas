unit Crypto4D.BigInteger.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework,
  Crypto4D.BigInteger;

type
  [TestFixture]
  TBigIntegerTests = class
  private
    function Hex(const Value: string): TBigInteger;
    function JsonHex(const TestCase: TJSONObject; const Name: string): TBigInteger;
    function HasValue(const TestCase: TJSONObject; const Name: string): Boolean;
    procedure CheckSame(const Expected, Actual: TBigInteger; const Index: Integer; const Operation: string);
    procedure CheckCase(const TestCase: TJSONObject; const Index: Integer);
    procedure CheckDivision(const TestCase: TJSONObject; const Index: Integer);
    procedure CheckModularOperations(const TestCase: TJSONObject; const Index: Integer);

  public
    [Test]
    [TestCase('Empty', ',00')]
    [TestCase('SingleZero', '00,00')]
    [TestCase('LeadingZeros', '000000000000000001,01')]
    [TestCase('OneLimb', 'ffffffff,ffffffff')]
    [TestCase('LimbPlusOneByte', '01ffffffff,01ffffffff')]
    [TestCase('OddDigitCount', 'abc,0abc')]
    [TestCase('UpperCase', 'DEADBEEF,deadbeef')]
    procedure FromHex_Various_RoundTripsToMinimalHex(const Input: string; const Expected: string);

    [Test]
    procedure FromHex_InvalidDigit_RaisesArgumentError;

    [Test]
    procedure FromBytes_EmptyArray_IsZero;

    [Test]
    procedure FromBytes_LeadingZeroBytes_AreIgnored;

    [Test]
    procedure ToBytes_Zero_IsSingleZeroByte;

    [Test]
    procedure ToFixedBytes_ShortValue_IsLeftPadded;

    [Test]
    procedure ToFixedBytes_ZeroInZeroBytes_IsEmpty;

    [Test]
    procedure ToFixedBytes_ValueTooLarge_RaisesArgumentError;

    [Test]
    procedure FromUInt64_MaxValue_HasSixtyFourBits;

    [Test]
    [TestCase('Zero', '0,0')]
    [TestCase('One', '1,1')]
    [TestCase('LimbBoundaryBelow', 'ffffffff,32')]
    [TestCase('LimbBoundaryAbove', '100000000,33')]
    [TestCase('TwoLimbs', '8000000000000000,64')]
    procedure BitLength_Various_ReturnsExpected(const Value: string; const Expected: Int64);

    [Test]
    procedure TestBit_BeyondValue_ReturnsFalse;

    [Test]
    procedure TestBit_NegativeIndex_RaisesArgumentError;

    [Test]
    [TestCase('ZeroPlusZero', '0,0,00')]
    [TestCase('CarryOverOneLimb', 'ffffffff,1,0100000000')]
    [TestCase('CarryOverTwoLimbs', 'ffffffffffffffff,1,010000000000000000')]
    [TestCase('CarryRipple', 'ffffffffffffffffffffffff,ffffffffffffffffffffffff,01fffffffffffffffffffffffe')]
    [TestCase('ShortPlusLong', '1,ffffffff00000000ffffffff,ffffffff0000000100000000')]
    procedure Add_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: string);

    [Test]
    [TestCase('EqualValues', 'ffffffffffffffff,ffffffffffffffff,00')]
    [TestCase('BorrowOverOneLimb', '100000000,1,ffffffff')]
    [TestCase('BorrowOverTwoLimbs', '10000000000000000,1,ffffffffffffffff')]
    [TestCase('BorrowRipple', '1000000000000000000000000,1,ffffffffffffffffffffffff')]
    procedure Subtract_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: string);

    [Test]
    procedure Subtract_LargerFromSmaller_RaisesArithmeticError;

    [Test]
    [TestCase('ByZero', 'ffffffffffffffff,0,00')]
    [TestCase('ByOne', 'ffffffffffffffff,1,ffffffffffffffff')]
    [TestCase('MaxLimbs', 'ffffffffffffffff,ffffffffffffffff,fffffffffffffffe0000000000000001')]
    procedure Multiply_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: string);

    [Test]
    [TestCase('ZeroDividend', '0,7,00,00')]
    [TestCase('SmallerDividend', '5,7,00,05')]
    [TestCase('EqualValues', 'ffffffffffffffffff,ffffffffffffffffff,01,00')]
    [TestCase('SingleLimbDivisor', '10000000000000000,3,5555555555555555,01')]
    [TestCase('AddBackStep', '800000000000000000000003,200000000000000000000001,03,200000000000000000000000')]
    procedure DivMod_Various_ReturnsExpected(const Dividend: string;
                                             const Divisor: string;
                                             const ExpectedQuotient: string;
                                             const ExpectedRemainder: string);

    [Test]
    procedure DivMod_LargeQuotient_MatchesReference;

    [Test]
    procedure DivMod_DivisorZero_RaisesArithmeticError;

    [Test]
    procedure ShiftLeft_AcrossLimbs_MatchesReference;

    [Test]
    procedure ShiftRight_AcrossLimbs_MatchesReference;

    [Test]
    procedure ShiftRight_BeyondBitLength_IsZero;

    [Test]
    procedure ShiftLeft_NegativeCount_RaisesArgumentError;

    [Test]
    [TestCase('Less', '1,2,-1')]
    [TestCase('Equal', 'ffffffffff,ffffffffff,0')]
    [TestCase('GreaterByLength', '100000000,ffffffff,1')]
    [TestCase('GreaterByLowLimb', '100000002,100000001,1')]
    procedure Compare_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: Integer);

    [Test]
    procedure ModPow_KnownValue_MatchesReference;

    [Test]
    procedure ModPow_ExponentZero_IsOne;

    [Test]
    procedure ModPow_ModulusOne_IsZero;

    [Test]
    procedure ModPow_ModulusZero_RaisesArithmeticError;

    [Test]
    procedure ModInverse_KnownValue_MatchesReference;

    [Test]
    [TestCase('Zero', '0,7')]
    [TestCase('SharedFactor', '6,9')]
    [TestCase('MultipleOfModulus', 'e,7')]
    [TestCase('EvenValueEvenModulus', '4,100000000000000000000')]
    procedure TryModInverse_NotInvertible_ReturnsFalse(const Value: string; const Modulus: string);

    [Test]
    procedure TryModInverse_ModulusOne_ReturnsZero;

    [Test]
    procedure TryModInverse_ValueAboveModulus_IsReducedFirst;

    [Test]
    procedure ModInverse_NotInvertible_RaisesArithmeticError;

    [Test]
    procedure TryModInverse_ModulusZero_RaisesArithmeticError;

    [Test]
    procedure ReferenceVectors_AllOperations_MatchReference;

    [Test]
    procedure ReferenceVectors_AddBackDivisions_MatchReference;
  end;

implementation

uses
  Crypto4D.Errors,
  Crypto4D.TestSupport;

const
  VectorFileName    = 'biginteger/biginteger.json';
  LeftName          = 'a';
  RightName         = 'b';
  SumName           = 'sum';
  ProductName       = 'product';
  RemainderName     = 'remainder';
  DifferenceName    = 'difference';
  QuotientName      = 'quotient';
  PowerName         = 'power';
  InverseName       = 'inverse';
  P256PrimeHex      = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff';
  SampleValueHex    = '123456789abcdef0123456789abcdef';

function TBigIntegerTests.Hex(const Value: string): TBigInteger;
begin
  Result := TBigInteger.FromHex(Value);
end;

function TBigIntegerTests.JsonHex(const TestCase: TJSONObject; const Name: string): TBigInteger;
begin
  const Hex = TestCase.GetValue<string>(Name);
  Result := TBigInteger.FromHex(Hex);
end;

function TBigIntegerTests.HasValue(const TestCase: TJSONObject; const Name: string): Boolean;
begin
  const Value = TestCase.GetValue(Name);
  Result := Assigned(Value) and not (Value is TJSONNull);
end;

procedure TBigIntegerTests.FromHex_Various_RoundTripsToMinimalHex(const Input: string; const Expected: string);
begin
  const Actual = Hex(Input).ToHex;

  Assert.AreEqual(Expected, Actual);
end;

procedure TBigIntegerTests.FromHex_InvalidDigit_RaisesArgumentError;
begin
  Assert.WillRaise(
    procedure
    begin
      TBigInteger.FromHex('12g4');
    end,
    ECrypto4DArgumentError);
end;

procedure TBigIntegerTests.FromBytes_EmptyArray_IsZero;
begin
  const Value = TBigInteger.FromBytes(nil);

  Assert.IsTrue(Value.IsZero);
  Assert.AreEqual<Int64>(0, Value.BitLength);
end;

procedure TBigIntegerTests.FromBytes_LeadingZeroBytes_AreIgnored;
begin
  const Value = TBigInteger.FromBytes([0, 0, 0, 0, 0, 1, 2]);

  Assert.AreEqual('0102', Value.ToHex);
  Assert.AreEqual<NativeInt>(2, Value.ByteLength);
end;

procedure TBigIntegerTests.ToBytes_Zero_IsSingleZeroByte;
begin
  const Bytes = TBigInteger.Zero.ToBytes;

  Assert.AreEqual('00', TTestSupport.BytesToHex(Bytes));
end;

procedure TBigIntegerTests.ToFixedBytes_ShortValue_IsLeftPadded;
begin
  const Bytes = Hex('0102030405').ToFixedBytes(8);

  Assert.AreEqual('0000000102030405', TTestSupport.BytesToHex(Bytes));
end;

procedure TBigIntegerTests.ToFixedBytes_ZeroInZeroBytes_IsEmpty;
begin
  const Bytes = TBigInteger.Zero.ToFixedBytes(0);

  Assert.AreEqual(0, Integer(Length(Bytes)));
end;

procedure TBigIntegerTests.ToFixedBytes_ValueTooLarge_RaisesArgumentError;
begin
  Assert.WillRaise(
    procedure
    begin
      Hex('010000').ToFixedBytes(2);
    end,
    ECrypto4DArgumentError);
end;

procedure TBigIntegerTests.FromUInt64_MaxValue_HasSixtyFourBits;
begin
  const Value = TBigInteger.FromUInt64(High(UInt64));

  Assert.AreEqual('ffffffffffffffff', Value.ToHex);
  Assert.AreEqual<Int64>(64, Value.BitLength);
end;

procedure TBigIntegerTests.BitLength_Various_ReturnsExpected(const Value: string; const Expected: Int64);
begin
  const Actual = Hex(Value).BitLength;

  Assert.AreEqual(Expected, Actual);
end;

procedure TBigIntegerTests.TestBit_BeyondValue_ReturnsFalse;
begin
  const Value = Hex('8000000000000001');

  Assert.IsTrue(Value.TestBit(0));
  Assert.IsFalse(Value.TestBit(1));
  Assert.IsTrue(Value.TestBit(63));
  Assert.IsFalse(Value.TestBit(64));
  Assert.IsFalse(Value.TestBit(100000));
end;

procedure TBigIntegerTests.TestBit_NegativeIndex_RaisesArgumentError;
begin
  Assert.WillRaise(
    procedure
    begin
      TBigInteger.One.TestBit(-1);
    end,
    ECrypto4DArgumentError);
end;

procedure TBigIntegerTests.Add_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: string);
begin
  const Sum = Hex(Left) + Hex(Right);

  Assert.AreEqual(Expected, Sum.ToHex);
end;

procedure TBigIntegerTests.Subtract_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: string);
begin
  const Difference = Hex(Left) - Hex(Right);

  Assert.AreEqual(Expected, Difference.ToHex);
end;

procedure TBigIntegerTests.Subtract_LargerFromSmaller_RaisesArithmeticError;
begin
  Assert.WillRaise(
    procedure
    begin
      const Difference = Hex('1') - Hex('2');
      Assert.Fail(Difference.ToHex);
    end,
    ECrypto4DArithmeticError);
end;

procedure TBigIntegerTests.Multiply_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: string);
begin
  const Product = Hex(Left) * Hex(Right);

  Assert.AreEqual(Expected, Product.ToHex);
end;

procedure TBigIntegerTests.DivMod_Various_ReturnsExpected(const Dividend: string;
                                                          const Divisor: string;
                                                          const ExpectedQuotient: string;
                                                          const ExpectedRemainder: string);
begin
  var Quotient: TBigInteger;
  var Remainder: TBigInteger;

  TBigInteger.DivMod(Hex(Dividend), Hex(Divisor), Quotient, Remainder);

  Assert.AreEqual(ExpectedQuotient, Quotient.ToHex);
  Assert.AreEqual(ExpectedRemainder, Remainder.ToHex);
end;

procedure TBigIntegerTests.DivMod_LargeQuotient_MatchesReference;
begin
  const AllOnes = (TBigInteger.One shl 4096) - TBigInteger.One;
  const Three   = TBigInteger.FromUInt64(3);

  const Quotient  = AllOnes div Three;
  const Remainder = AllOnes mod Three;

  Assert.AreEqual(string.Create('5', 1024), Quotient.ToHex);
  Assert.IsTrue(Remainder.IsZero);
  Assert.IsTrue(Quotient * Three = AllOnes);
end;

procedure TBigIntegerTests.DivMod_DivisorZero_RaisesArithmeticError;
begin
  Assert.WillRaise(
    procedure
    begin
      const Quotient = Hex('1234') div TBigInteger.Zero;
      Assert.Fail(Quotient.ToHex);
    end,
    ECrypto4DArithmeticError);
end;

procedure TBigIntegerTests.ShiftLeft_AcrossLimbs_MatchesReference;
begin
  const Shifted = Hex(SampleValueHex) shl 67;

  Assert.AreEqual('091a2b3c4d5e6f78091a2b3c4d5e6f780000000000000000', Shifted.ToHex);
end;

procedure TBigIntegerTests.ShiftRight_AcrossLimbs_MatchesReference;
begin
  const Shifted = Hex(SampleValueHex) shr 67;

  Assert.AreEqual('2468acf13579bd', Shifted.ToHex);
end;

procedure TBigIntegerTests.ShiftRight_BeyondBitLength_IsZero;
begin
  const Shifted = Hex(SampleValueHex) shr 4096;

  Assert.IsTrue(Shifted.IsZero);
end;

procedure TBigIntegerTests.ShiftLeft_NegativeCount_RaisesArgumentError;
begin
  Assert.WillRaise(
    procedure
    begin
      const Shifted = TBigInteger.One shl -1;
      Assert.Fail(Shifted.ToHex);
    end,
    ECrypto4DArgumentError);
end;

procedure TBigIntegerTests.Compare_Various_ReturnsExpected(const Left: string; const Right: string; const Expected: Integer);
begin
  const Actual = TBigInteger.Compare(Hex(Left), Hex(Right));

  Assert.AreEqual(Expected, Actual);
end;

procedure TBigIntegerTests.ModPow_KnownValue_MatchesReference;
begin
  const Power = Hex(SampleValueHex).ModPow(Hex('fedcba9876543210'), Hex(P256PrimeHex));

  Assert.AreEqual('630c3e025cc63619d557ec6a91b28e205e3729060d8a5ef7d7d0e3fd4fbc2ce1', Power.ToHex);
end;

procedure TBigIntegerTests.ModPow_ExponentZero_IsOne;
begin
  const Power = TBigInteger.Zero.ModPow(TBigInteger.Zero, Hex('7'));

  Assert.IsTrue(Power.IsOne);
end;

procedure TBigIntegerTests.ModPow_ModulusOne_IsZero;
begin
  const Power = Hex('5').ModPow(Hex('3'), TBigInteger.One);

  Assert.IsTrue(Power.IsZero);
end;

procedure TBigIntegerTests.ModPow_ModulusZero_RaisesArithmeticError;
begin
  Assert.WillRaise(
    procedure
    begin
      Hex('5').ModPow(Hex('3'), TBigInteger.Zero);
    end,
    ECrypto4DArithmeticError);
end;

procedure TBigIntegerTests.ModInverse_KnownValue_MatchesReference;
begin
  const Inverse = Hex(SampleValueHex).ModInverse(Hex(P256PrimeHex));

  Assert.AreEqual('c5fe6af474c4725cefbe3e8027b286f5b218d5c5250f7841e4241c0fe3903607', Inverse.ToHex);
end;

procedure TBigIntegerTests.TryModInverse_NotInvertible_ReturnsFalse(const Value: string; const Modulus: string);
begin
  var Inverse: TBigInteger;

  const Found = Hex(Value).TryModInverse(Hex(Modulus), Inverse);

  Assert.IsFalse(Found);
  Assert.IsTrue(Inverse.IsZero);
end;

procedure TBigIntegerTests.TryModInverse_ModulusOne_ReturnsZero;
begin
  var Inverse: TBigInteger;

  const Found = Hex('5').TryModInverse(TBigInteger.One, Inverse);

  Assert.IsTrue(Found);
  Assert.IsTrue(Inverse.IsZero);
end;

procedure TBigIntegerTests.TryModInverse_ValueAboveModulus_IsReducedFirst;
begin
  var Inverse: TBigInteger;

  const Found = Hex('a').TryModInverse(Hex('7'), Inverse);

  Assert.IsTrue(Found);
  Assert.AreEqual('05', Inverse.ToHex);
end;

procedure TBigIntegerTests.ModInverse_NotInvertible_RaisesArithmeticError;
begin
  Assert.WillRaise(
    procedure
    begin
      Hex('6').ModInverse(Hex('9'));
    end,
    ECrypto4DArithmeticError);
end;

procedure TBigIntegerTests.TryModInverse_ModulusZero_RaisesArithmeticError;
begin
  Assert.WillRaise(
    procedure
    begin
      var Inverse: TBigInteger;
      Hex('6').TryModInverse(TBigInteger.Zero, Inverse);
    end,
    ECrypto4DArithmeticError);
end;

procedure TBigIntegerTests.CheckSame(const Expected, Actual: TBigInteger; const Index: Integer; const Operation: string);
begin
  const IsSame = (Expected = Actual);
  if not IsSame then
    Assert.FailFmt('case %d, %s: expected %s but got %s', [Index, Operation, Expected.ToHex, Actual.ToHex]);
end;

procedure TBigIntegerTests.CheckCase(const TestCase: TJSONObject; const Index: Integer);
begin
  const Left  = JsonHex(TestCase, LeftName);
  const Right = JsonHex(TestCase, RightName);

  const ExpectedSum      = JsonHex(TestCase, SumName);
  const ExpectedProduct  = JsonHex(TestCase, ProductName);
  const ExpectedOrder    = TestCase.GetValue<Integer>('compare');
  const ActualOrder      = TBigInteger.Compare(Left, Right);
  CheckSame(ExpectedSum, Left + Right, Index, SumName);
  CheckSame(ExpectedProduct, Left * Right, Index, ProductName);
  Assert.AreEqual(ExpectedOrder, ActualOrder, Format('case %d, compare', [Index]));

  if HasValue(TestCase, DifferenceName) then
  begin
    const ExpectedDifference = JsonHex(TestCase, DifferenceName);
    CheckSame(ExpectedDifference, Left - Right, Index, DifferenceName);
  end;

  if HasValue(TestCase, QuotientName) then
    CheckDivision(TestCase, Index);

  if HasValue(TestCase, PowerName) then
    CheckModularOperations(TestCase, Index);
end;

procedure TBigIntegerTests.CheckDivision(const TestCase: TJSONObject; const Index: Integer);
begin
  const Dividend = JsonHex(TestCase, LeftName);
  const Divisor  = JsonHex(TestCase, RightName);

  const ExpectedQuotient  = JsonHex(TestCase, QuotientName);
  const ExpectedRemainder = JsonHex(TestCase, RemainderName);
  CheckSame(ExpectedQuotient, Dividend div Divisor, Index, QuotientName);
  CheckSame(ExpectedRemainder, Dividend mod Divisor, Index, RemainderName);
end;

procedure TBigIntegerTests.CheckModularOperations(const TestCase: TJSONObject; const Index: Integer);
begin
  const Value    = JsonHex(TestCase, LeftName);
  const Modulus  = JsonHex(TestCase, 'm');
  const Exponent = JsonHex(TestCase, 'exponent');

  const ExpectedPower = JsonHex(TestCase, PowerName);
  const ActualPower   = Value.ModPow(Exponent, Modulus);
  CheckSame(ExpectedPower, ActualPower, Index, PowerName);

  var Inverse: TBigInteger;
  const Found         = Value.TryModInverse(Modulus, Inverse);
  const ExpectedFound = HasValue(TestCase, InverseName);
  Assert.AreEqual(ExpectedFound, Found, Format('case %d, inverse exists', [Index]));
  if Found then
  begin
    const ExpectedInverse = JsonHex(TestCase, InverseName);
    CheckSame(ExpectedInverse, Inverse, Index, InverseName);
  end;
end;

procedure TBigIntegerTests.ReferenceVectors_AllOperations_MatchReference;
begin
  const Document = TTestSupport.LoadJsonObject(VectorFileName);
  try
    const Cases = TTestSupport.ArrayOf(Document, 'cases');
    for var Index := 0 to Cases.Count - 1 do
    begin
      const TestCase = TTestSupport.ObjectAt(Cases, Index);
      CheckCase(TestCase, Index);
    end;

    const Summary  = Format('%d big integer reference cases checked', [Cases.Count]);
    const HasCases = (Cases.Count > 0);
    TTestSupport.Log(Summary);
    Assert.IsTrue(HasCases);
  finally
    Document.Free;
  end;
end;

procedure TBigIntegerTests.ReferenceVectors_AddBackDivisions_MatchReference;
begin
  const Document = TTestSupport.LoadJsonObject(VectorFileName);
  try
    const Cases = TTestSupport.ArrayOf(Document, 'addBackCases');
    for var Index := 0 to Cases.Count - 1 do
    begin
      const TestCase = TTestSupport.ObjectAt(Cases, Index);
      CheckDivision(TestCase, Index);
    end;

    const Summary  = Format('%d divisions that need the add-back step checked', [Cases.Count]);
    const HasCases = (Cases.Count > 0);
    TTestSupport.Log(Summary);
    Assert.IsTrue(HasCases);
  finally
    Document.Free;
  end;
end;

end.
