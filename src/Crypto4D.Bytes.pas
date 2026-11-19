unit Crypto4D.Bytes;

interface

uses
  System.SysUtils;

type
  TByteArrays = class
  public
    class function AreEqual(const Left, Right: TBytes): Boolean; static;
  end;

implementation

class function TByteArrays.AreEqual(const Left, Right: TBytes): Boolean;
begin
  const SameLength = (Length(Left) = Length(Right));
  if not SameLength then
    Exit(False);

  var Difference: Byte := 0;
  for var Index := 0 to High(Left) do
  begin
    Difference := Difference or (Left[Index] xor Right[Index]);
  end;

  Result := (Difference = 0);
end;

end.
