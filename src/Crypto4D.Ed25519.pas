unit Crypto4D.Ed25519;

interface

uses
  System.SysUtils;

type
  TEd25519 = class
  private
    class procedure GuardPublicKey(const PublicKey: TBytes); static;

  public
    const
      PublicKeySize = 32;
      SignatureSize = 64;

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
