unit Crypto4D.Ed25519;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   Verifies Ed25519 signatures (RFC 8032, pure Ed25519 without context or prehash).
  /// </summary>
  TEd25519 = class
  private
    class procedure GuardPublicKey(const PublicKey: TBytes); static;

  public
    const
      PublicKeySize = 32;
      SignatureSize = 64;

    /// <summary>
    ///   Verifies a signature with the strict rules: the equation [S]B = R + [k]A is checked without multiplying by
    ///   the cofactor.
    /// </summary>
    /// <param name="PublicKey">Encoded public key A, 32 bytes.</param>
    /// <param name="Message">The signed message; may be empty.</param>
    /// <param name="Signature">64 bytes: the encoded point R followed by the scalar S in little-endian.</param>
    /// <returns>True when the signature is valid. False when Signature is not 64 bytes, S is not below the group
    ///   order L, PublicKey or R is not in canonical encoding or not a point on the curve, PublicKey is a point of
    ///   small order, or the signature does not match.</returns>
    /// <exception cref="ECrypto4DArgumentError">PublicKey is not 32 bytes.</exception>
    class function Verify(const PublicKey, Message, Signature: TBytes): Boolean; static;
  end;

implementation

uses
  Crypto4D.Errors,
  Crypto4D.Bytes,
  Crypto4D.BigInteger,
  Crypto4D.Hash,
  Crypto4D.Edwards25519;

resourcestring
  InvalidPublicKeySize = 'An Ed25519 public key must be %d bytes, but this one is %d bytes';

class function TEd25519.Verify(const PublicKey, Message, Signature: TBytes): Boolean;
begin
  GuardPublicKey(PublicKey);

  const HasValidSize = (Length(Signature) = SignatureSize);
  if not HasValidSize then
    Exit(False);

  const Curve = TEdwards25519Curve.Create;
  var KeyPoint: TEdwardsPoint;
  if not Curve.TryDecode(PublicKey, KeyPoint) then
    Exit(False);
  if Curve.HasSmallOrder(KeyPoint) then
    Exit(False);

  const EncodedR   = Copy(Signature, 0, TEdwards25519Curve.EncodedSize);
  const EncodedS   = Copy(Signature, TEdwards25519Curve.EncodedSize, TEdwards25519Curve.EncodedSize);
  const S          = TEdwards25519Curve.LittleEndianToInteger(EncodedS);
  const SIsReduced = (S < Curve.Order);
  if not SIsReduced then
    Exit(False);

  const HashInput   = EncodedR + PublicKey + Message;
  const Digest      = TCryptoHash.Sha512(HashInput);
  const DigestValue = TEdwards25519Curve.LittleEndianToInteger(Digest);
  const Challenge   = DigestValue mod Curve.Order;

  const NegatedKey       = Curve.Negate(KeyPoint);
  const Candidate        = Curve.MultiplyTwo(S, Challenge, NegatedKey);
  const EncodedCandidate = Curve.Encode(Candidate);

  Result := TByteArrays.AreEqual(EncodedCandidate, EncodedR);
end;

class procedure TEd25519.GuardPublicKey(const PublicKey: TBytes);
begin
  const HasValidSize = (Length(PublicKey) = PublicKeySize);
  if not HasValidSize then
    raise ECrypto4DArgumentError.CreateFmt(InvalidPublicKeySize, [PublicKeySize, Length(PublicKey)]);
end;

end.
