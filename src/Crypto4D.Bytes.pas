unit Crypto4D.Bytes;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   Helpers for byte arrays.
  /// </summary>
  TByteArrays = class
  public
    /// <summary>
    ///   Compares two byte arrays. All bytes are compared; the loop does not stop at the first difference.
    /// </summary>
    /// <param name="Left">First array; may be empty.</param>
    /// <param name="Right">Second array; may be empty.</param>
    /// <returns>True when both arrays have the same length and the same content. False when the lengths
    ///   differ.</returns>
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
