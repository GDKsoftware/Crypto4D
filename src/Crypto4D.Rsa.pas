unit Crypto4D.Rsa;

interface

uses
  System.SysUtils;

type
  TRsaPublicKey = record
  private
    FModulus: TBytes;
    FExponent: TBytes;

  public
    const
      MinimumModulusBits  = 2048;
      MaximumModulusBits  = 16384;
      MinimumExponent     = 3;
      MaximumExponentBits = 64;

    class function Create(const Modulus, Exponent: TBytes): TRsaPublicKey; static;
    class function IsSupportedModulus(const Modulus: TBytes): Boolean; static;
    class function IsSupportedExponent(const Exponent: TBytes): Boolean; static;
    class procedure GuardModulus(const Modulus: TBytes); static;
    class procedure GuardExponent(const Exponent: TBytes); static;

    property Modulus: TBytes read FModulus;
    property Exponent: TBytes read FExponent;
  end;

  TRsaPkcs1Sha256 = class
  private
    const
      PaddingByte   = $FF;
      BlockType     = $01;
      FixedOverhead = 3;

    class function ExpectedEncodedMessage(const Message: TBytes; const EncodedSize: Integer): TBytes; static;
    class function Sha256DigestInfoPrefix: TBytes; static;

  public
    class function Verify(const PublicKey: TRsaPublicKey; const Message, Signature: TBytes): Boolean; static;
  end;

implementation

uses
  Crypto4D.Errors,
  Crypto4D.Bytes,
  Crypto4D.BigInteger,
  Crypto4D.Hash;

resourcestring
  UnsupportedModulusSize = 'An RSA modulus must be between %d and %d bits, but this one is %d bits';
  UnsupportedExponent    = 'An RSA public exponent must be odd, at least %d and at most %d bits, but this one is 0x%s';

class function TRsaPublicKey.Create(const Modulus, Exponent: TBytes): TRsaPublicKey;
begin
  GuardModulus(Modulus);
  GuardExponent(Exponent);

  Result.FModulus  := Copy(Modulus);
  Result.FExponent := Copy(Exponent);
end;

class function TRsaPublicKey.IsSupportedModulus(const Modulus: TBytes): Boolean;
begin
  const Value       = TBigInteger.FromBytes(Modulus);
  const ModulusBits = Value.BitLength;

  Result := (ModulusBits >= MinimumModulusBits) and (ModulusBits <= MaximumModulusBits);
end;

class function TRsaPublicKey.IsSupportedExponent(const Exponent: TBytes): Boolean;
begin
  const Value   = TBigInteger.FromBytes(Exponent);
  const Minimum = TBigInteger.FromUInt64(MinimumExponent);

  Result := Value.IsOdd and (Value >= Minimum) and (Value.BitLength <= MaximumExponentBits);
end;

class procedure TRsaPublicKey.GuardModulus(const Modulus: TBytes);
begin
  if IsSupportedModulus(Modulus) then
    Exit;

  const Value = TBigInteger.FromBytes(Modulus);
  raise ECrypto4DArgumentError.CreateFmt(UnsupportedModulusSize, [MinimumModulusBits, MaximumModulusBits, Value.BitLength]);
end;

class procedure TRsaPublicKey.GuardExponent(const Exponent: TBytes);
begin
  if IsSupportedExponent(Exponent) then
    Exit;

  const Value = TBigInteger.FromBytes(Exponent);
  raise ECrypto4DArgumentError.CreateFmt(UnsupportedExponent, [MinimumExponent, MaximumExponentBits, Value.ToHex]);
end;

class function TRsaPkcs1Sha256.Verify(const PublicKey: TRsaPublicKey; const Message, Signature: TBytes): Boolean;
begin
  TRsaPublicKey.GuardModulus(PublicKey.Modulus);
  TRsaPublicKey.GuardExponent(PublicKey.Exponent);

  const Modulus      = TBigInteger.FromBytes(PublicKey.Modulus);
  const Exponent     = TBigInteger.FromBytes(PublicKey.Exponent);
  const ModulusSize  = Modulus.ByteLength;
  const HasValidSize = (Length(Signature) = ModulusSize);
  if not HasValidSize then
    Exit(False);

  const SignatureValue = TBigInteger.FromBytes(Signature);
  const IsBelowModulus = (SignatureValue < Modulus);
  if not IsBelowModulus then
    Exit(False);

  const Recovered = SignatureValue.ModPow(Exponent, Modulus);
  const Actual    = Recovered.ToFixedBytes(ModulusSize);
  const Expected  = ExpectedEncodedMessage(Message, ModulusSize);

  Result := TByteArrays.AreEqual(Expected, Actual);
end;

class function TRsaPkcs1Sha256.ExpectedEncodedMessage(const Message: TBytes; const EncodedSize: Integer): TBytes;
begin
  const Digest        = TCryptoHash.Sha256(Message);
  const DigestInfo    = Sha256DigestInfoPrefix + Digest;
  const PaddingLength = EncodedSize - Length(DigestInfo) - FixedOverhead;

  SetLength(Result, EncodedSize);
  Result[0] := $00;
  Result[1] := BlockType;
  for var Index := 2 to PaddingLength + 1 do
  begin
    Result[Index] := PaddingByte;
  end;
  Result[PaddingLength + 2] := $00;
  Move(DigestInfo[0], Result[PaddingLength + FixedOverhead], Length(DigestInfo));
end;

class function TRsaPkcs1Sha256.Sha256DigestInfoPrefix: TBytes;
begin
  Result := TBytes.Create($30, $31, $30, $0D, $06, $09, $60, $86, $48, $01, $65, $03, $04, $02, $01, $05, $00, $04, $20);
end;

end.
