unit Crypto4D.LargeInput.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework;

type
  [TestFixture]
  [Category('LargeInput')]
  TLargeInputTests = class
  private
    const
      FourGiB: Int64         = $100000000;
      TwoGiB: Int64          = $80000000;
      BitsBeyondFourGiBits   = 2048;
      BitsPerByte            = 8;
      ByteMask               = $FF;
      TopBitOnly             = $80;
      LowBitOnly             = $01;
      OctetStringTag         = $04;
      LongFormWithFourOctets = $84;
      FirstLengthOctet       = 2;
      LengthOctetCount       = 4;
      DerHeaderBytes         = FirstLengthOctet + LengthOctetCount;
      Sha256OfFourGiBPlusOne = 'd6cba2fb80a815340cd82d98754730a8e86af2d14a136d3b20bbc1e13ece5c11';
      Sha512OfFourGiBPlusOne = '21d2c186400ef41842a08473de6bc76fda12ae93b3984ff0ceaad66c508d26f0' +
                               '8d827e2a4f6e2b7f0b75bf22be354fe37d5fd9fda1f27d688d24c70b9b9f698b';

    {$IFDEF CPU64BITS}
    function ZerosFollowedByOne(const ZeroCount: Int64): TBytes;
    function OddModulusWithBitLength(const BitLength: Int64): TBytes;
    function DerOctetStringWithLength(const ContentLength: Int64): TBytes;
    {$ENDIF}

  public
    [Test]
    procedure BitLength_ValueOfTwoToTheThirtyOneBits_IsTwoToTheThirtyOne;

    [Test]
    procedure TestBit_HighestBitBeyondTwoToTheThirtyOne_IsSet;

    {$IFDEF CPU64BITS}
    [Test]
    procedure Sha256_MessageOfFourGiBPlusOneByte_HashesEveryByte;

    [Test]
    procedure Sha512_MessageOfFourGiBPlusOneByte_HashesEveryByte;

    [Test]
    procedure CreateRsaKey_ModulusOfFourGiBitsPlus2048Bits_RaisesArgumentError;

    [Test]
    procedure TryRead_ContentOfTwoGiB_ReturnsFalse;
    {$ENDIF}
  end;

implementation

uses
  Crypto4D.Errors,
  Crypto4D.BigInteger,
  Crypto4D.Hash,
  Crypto4D.Rsa,
  Crypto4D.Der,
  Crypto4D.TestSupport;

procedure TLargeInputTests.BitLength_ValueOfTwoToTheThirtyOneBits_IsTwoToTheThirtyOne;
begin
  const Expected: Int64 = TwoGiB;
  const Value           = TBigInteger.One shl MaxInt;

  const Actual = Value.BitLength;

  Assert.AreEqual<Int64>(Expected, Actual);
end;

procedure TLargeInputTests.TestBit_HighestBitBeyondTwoToTheThirtyOne_IsSet;
begin
  const Value           = (TBigInteger.One shl MaxInt) shl 1;
  const BitIndex: Int64 = TwoGiB;

  const IsSet = Value.TestBit(BitIndex);

  Assert.IsTrue(IsSet);
end;

{$IFDEF CPU64BITS}

procedure TLargeInputTests.Sha256_MessageOfFourGiBPlusOneByte_HashesEveryByte;
begin
  const Message = ZerosFollowedByOne(FourGiB);

  const Digest    = TCryptoHash.Sha256(Message);
  const DigestHex = TTestSupport.BytesToHex(Digest);

  Assert.AreEqual(Sha256OfFourGiBPlusOne, DigestHex);
end;

procedure TLargeInputTests.Sha512_MessageOfFourGiBPlusOneByte_HashesEveryByte;
begin
  const Message = ZerosFollowedByOne(FourGiB);

  const Digest    = TCryptoHash.Sha512(Message);
  const DigestHex = TTestSupport.BytesToHex(Digest);

  Assert.AreEqual(Sha512OfFourGiBPlusOne, DigestHex);
end;

procedure TLargeInputTests.CreateRsaKey_ModulusOfFourGiBitsPlus2048Bits_RaisesArgumentError;
begin
  const Modulus  = OddModulusWithBitLength(FourGiB + BitsBeyondFourGiBits);
  const Exponent = TTestSupport.HexToBytes('010001');

  Assert.WillRaise(
    procedure
    begin
      TRsaPublicKey.Create(Modulus, Exponent);
    end,
    ECrypto4DArgumentError);
end;

procedure TLargeInputTests.TryRead_ContentOfTwoGiB_ReturnsFalse;
begin
  const Data = DerOctetStringWithLength(TwoGiB);
  var Reader := TDerReader.Create(Data);

  var Element: TDerElement;
  const IsRead = Reader.TryRead(Element);

  Assert.IsFalse(IsRead);
end;

function TLargeInputTests.ZerosFollowedByOne(const ZeroCount: Int64): TBytes;
begin
  SetLength(Result, ZeroCount + 1);
  Result[ZeroCount] := 1;
end;

function TLargeInputTests.OddModulusWithBitLength(const BitLength: Int64): TBytes;
begin
  const ByteCount = BitLength div BitsPerByte;
  SetLength(Result, ByteCount);
  Result[0]             := TopBitOnly;
  Result[ByteCount - 1] := LowBitOnly;
end;

function TLargeInputTests.DerOctetStringWithLength(const ContentLength: Int64): TBytes;
begin
  SetLength(Result, DerHeaderBytes + ContentLength);
  Result[0] := OctetStringTag;
  Result[1] := LongFormWithFourOctets;
  for var OctetIndex := 0 to LengthOctetCount - 1 do
  begin
    const Shift = (LengthOctetCount - 1 - OctetIndex) * BitsPerByte;
    Result[FirstLengthOctet + OctetIndex] := Byte((ContentLength shr Shift) and ByteMask);
  end;
end;

{$ENDIF}

end.
