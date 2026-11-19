unit Crypto4D.Rsa;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   An RSA public key: modulus and public exponent.
  /// </summary>
  TRsaPublicKey = record
  private
    FModulus: TBytes;
    FExponent: TBytes;

    class function IsSupportedModulusSize(const ModulusBits: Integer): Boolean; static;

  public
    const
      MinimumModulusBits  = 2048;
      MaximumModulusBits  = 8192;
      MinimumExponent     = 3;
      MaximumExponentBits = 33;

    /// <summary>
    ///   Creates a key and checks its limits. For a key from an untrusted source, call IsSupportedModulus and
    ///   IsSupportedExponent first when an exception is not wanted.
    /// </summary>
    /// <param name="Modulus">The modulus n as big-endian bytes: odd and from 2048 up to 8192 bits. Leading zero
    ///   bytes are allowed.</param>
    /// <param name="Exponent">The public exponent e as big-endian bytes: odd, at least 3 and smaller than 2^33.
    ///   Leading zero bytes are allowed.</param>
    /// <exception cref="ECrypto4DArgumentError">The modulus or the exponent is outside these limits.</exception>
    class function Create(const Modulus, Exponent: TBytes): TRsaPublicKey; static;

    /// <summary>
    ///   True when the modulus, as big-endian bytes, is odd and from 2048 up to 8192 bits long.
    /// </summary>
    class function IsSupportedModulus(const Modulus: TBytes): Boolean; static;

    /// <summary>
    ///   True when the exponent, as big-endian bytes, is odd, at least 3 and smaller than 2^33.
    /// </summary>
    class function IsSupportedExponent(const Exponent: TBytes): Boolean; static;

    /// <summary>
    ///   Raises when IsSupportedModulus is False.
    /// </summary>
    /// <exception cref="ECrypto4DArgumentError">The modulus is even, under 2048 bits or over 8192
    ///   bits.</exception>
    class procedure GuardModulus(const Modulus: TBytes); static;

    /// <summary>
    ///   Raises when IsSupportedExponent is False.
    /// </summary>
    /// <exception cref="ECrypto4DArgumentError">The exponent is even, smaller than 3, or 2^33 or
    ///   larger.</exception>
    class procedure GuardExponent(const Exponent: TBytes); static;

    /// <summary>
    ///   The modulus as big-endian bytes, as given to Create.
    /// </summary>
    property Modulus: TBytes read FModulus;

    /// <summary>
    ///   The public exponent as big-endian bytes, as given to Create.
    /// </summary>
    property Exponent: TBytes read FExponent;
  end;

  /// <summary>
  ///   Verifies RSA signatures with PKCS #1 v1.5 padding and SHA-256 (RS256).
  /// </summary>
  TRsaPkcs1Sha256 = class
  private
    const
      PaddingByte   = $FF;
      BlockType     = $01;
      FixedOverhead = 3;

    class function ExpectedEncodedMessage(const Message: TBytes; const EncodedSize: Integer): TBytes; static;
    class function Sha256DigestInfoPrefix: TBytes; static;

  public
    /// <summary>
    ///   Verifies a signature. The expected encoded message is built and compared as a whole; the padding is not
    ///   parsed.
    /// </summary>
    /// <param name="PublicKey">Key of the signer.</param>
    /// <param name="Message">The signed message itself, not its digest; may be empty.</param>
    /// <param name="Signature">Big-endian bytes, exactly as long as the modulus.</param>
    /// <returns>True when the signature is valid. False when Signature has another length than the modulus, its
    ///   value is not below the modulus, or the signature does not match. A DigestInfo without the NULL parameter
    ///   does not match.</returns>
    /// <exception cref="ECrypto4DArgumentError">PublicKey is outside the limits of TRsaPublicKey.Create, as with a
    ///   key that was never assigned.</exception>
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
  EvenModulus            = 'An RSA modulus must be odd, but this one is even';
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

  Result := Value.IsOdd and IsSupportedModulusSize(ModulusBits);
end;

class function TRsaPublicKey.IsSupportedModulusSize(const ModulusBits: Integer): Boolean;
begin
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

  const Value       = TBigInteger.FromBytes(Modulus);
  const ModulusBits = Value.BitLength;
  if not IsSupportedModulusSize(ModulusBits) then
    raise ECrypto4DArgumentError.CreateFmt(UnsupportedModulusSize, [MinimumModulusBits, MaximumModulusBits, ModulusBits]);

  raise ECrypto4DArgumentError.Create(EvenModulus);
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
