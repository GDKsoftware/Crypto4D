unit Crypto4D.Hash;

interface

uses
  System.SysUtils,
  System.Hash;

type
  /// <summary>
  ///   SHA-2 digests, computed with the hash implementation of the Delphi RTL.
  /// </summary>
  TCryptoHash = class
  private
    const
      MaxUpdateLength = 1 shl 30;

    class function Digest(const Message: TBytes; const Version: THashSHA2.TSHA2Version): TBytes; static;

  public
    const
      Sha256Size = 32;
      Sha512Size = 64;

    /// <summary>
    ///   Computes the SHA-256 digest of a message.
    /// </summary>
    /// <param name="Message">Bytes to hash; may be empty.</param>
    /// <returns>The digest, 32 bytes.</returns>
    class function Sha256(const Message: TBytes): TBytes; static;

    /// <summary>
    ///   Computes the SHA-512 digest of a message.
    /// </summary>
    /// <param name="Message">Bytes to hash; may be empty.</param>
    /// <returns>The digest, 64 bytes.</returns>
    class function Sha512(const Message: TBytes): TBytes; static;
  end;

implementation

uses
  System.Math;

class function TCryptoHash.Sha256(const Message: TBytes): TBytes;
begin
  Result := Digest(Message, THashSHA2.TSHA2Version.SHA256);
end;

class function TCryptoHash.Sha512(const Message: TBytes): TBytes;
begin
  Result := Digest(Message, THashSHA2.TSHA2Version.SHA512);
end;

class function TCryptoHash.Digest(const Message: TBytes; const Version: THashSHA2.TSHA2Version): TBytes;
begin
  var Hasher := THashSHA2.Create(Version);

  const MessageLength = Length(Message);
  var Offset: NativeInt := 0;
  while Offset < MessageLength do
  begin
    const ChunkLength = Min(MessageLength - Offset, MaxUpdateLength);
    Hasher.Update(Message[Offset], Cardinal(ChunkLength));
    Inc(Offset, ChunkLength);
  end;

  Result := Hasher.HashAsBytes;
end;

end.
