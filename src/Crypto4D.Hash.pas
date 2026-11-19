unit Crypto4D.Hash;

interface

uses
  System.SysUtils,
  System.Hash;

type
  TCryptoHash = class
  private
    class function Digest(const Message: TBytes; const Version: THashSHA2.TSHA2Version): TBytes; static;

  public
    const
      Sha256Size = 32;
      Sha512Size = 64;

    class function Sha256(const Message: TBytes): TBytes; static;
    class function Sha512(const Message: TBytes): TBytes; static;
  end;

implementation

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
  const HasContent    = (MessageLength > 0);
  if HasContent then
    Hasher.Update(Message[0], MessageLength);

  Result := Hasher.HashAsBytes;
end;

end.
