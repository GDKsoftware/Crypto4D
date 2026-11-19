unit Crypto4D.TestSupport;

interface

uses
  System.SysUtils,
  System.JSON;

type
  ETestSupportError = class(Exception);

  TTestSupport = class
  private
    const
      VectorsFolder     = 'vectors';
      TestsFolder       = 'tests';
      HexDigitsPerByte  = 2;
      DerShortFormLimit = $80;
      DerLongFormFlag   = $80;

    class function FindVectorsRoot: string; static;
    class function HexDigitValue(const Digit: Char): Byte; static;

  public
    class function VectorFile(const RelativePath: string): string; static;
    class function LoadJsonObject(const RelativePath: string): TJSONObject; static;
    class function ArrayOf(const Parent: TJSONObject; const Name: string): TJSONArray; static;
    class function ObjectAt(const Items: TJSONArray; const Index: Integer): TJSONObject; static;
    class function IntegerAt(const Items: TJSONArray; const Index: Integer): Integer; static;
    class function LoadBytes(const RelativePath: string): TBytes; static;
    class function BytesOf(const Source: TJSONObject; const Name: string): TBytes; static;
    class function HexToBytes(const Hex: string): TBytes; static;
    class function BytesToHex(const Bytes: TBytes): string; static;
    class function FlipBit(const Bytes: TBytes; const BitIndex: Integer): TBytes; static;
    class function DerElement(const Tag: Byte; const Content: TBytes): TBytes; static;
    class procedure Log(const Text: string); static;
  end;

implementation

uses
  System.IOUtils,
  System.Generics.Collections,
  DUnitX.TestFramework;

resourcestring
  VectorsNotFound  = 'Folder "%s" was not found next to or above "%s"';
  InvalidHexDigit  = 'Invalid hexadecimal digit "%s"';
  OddHexLength     = 'Hexadecimal text has an odd length of %d';
  JsonObjectWanted = 'File "%s" does not hold a JSON object';

class function TTestSupport.VectorFile(const RelativePath: string): string;
begin
  const NativePath = RelativePath.Replace('/', TPath.DirectorySeparatorChar);
  Result := TPath.Combine(FindVectorsRoot, NativePath);
end;

class function TTestSupport.FindVectorsRoot: string;
begin
  const StartFolder = TPath.GetDirectoryName(TPath.GetFullPath(ParamStr(0)));
  var Folder := StartFolder;

  while not Folder.IsEmpty do
  begin
    const Direct = TPath.Combine(Folder, VectorsFolder);
    if TDirectory.Exists(Direct) then
      Exit(Direct);

    const BelowTests = TPath.Combine(TPath.Combine(Folder, TestsFolder), VectorsFolder);
    if TDirectory.Exists(BelowTests) then
      Exit(BelowTests);

    const Parent = TPath.GetDirectoryName(Folder);
    const ReachedRoot = (Parent = Folder);
    if ReachedRoot then
      Break;
    Folder := Parent;
  end;

  raise ETestSupportError.CreateFmt(VectorsNotFound, [VectorsFolder, StartFolder]);
end;

class function TTestSupport.LoadJsonObject(const RelativePath: string): TJSONObject;
begin
  const FileName = VectorFile(RelativePath);
  const Content  = TFile.ReadAllBytes(FileName);
  const Parsed   = TJSONObject.ParseJSONValue(Content, 0);

  const IsObject = (Parsed is TJSONObject);
  if not IsObject then
  begin
    Parsed.Free;
    raise ETestSupportError.CreateFmt(JsonObjectWanted, [FileName]);
  end;

  Result := TJSONObject(Parsed);
end;

class function TTestSupport.ArrayOf(const Parent: TJSONObject; const Name: string): TJSONArray;
begin
  Result := Parent.GetValue<TJSONArray>(Name);
end;

class function TTestSupport.ObjectAt(const Items: TJSONArray; const Index: Integer): TJSONObject;
begin
  Result := Items.Items[Index] as TJSONObject;
end;

class function TTestSupport.IntegerAt(const Items: TJSONArray; const Index: Integer): Integer;
begin
  Result := Items.Items[Index].GetValue<Integer>;
end;

class function TTestSupport.LoadBytes(const RelativePath: string): TBytes;
begin
  const FileName = VectorFile(RelativePath);
  Result := TFile.ReadAllBytes(FileName);
end;

class function TTestSupport.BytesOf(const Source: TJSONObject; const Name: string): TBytes;
begin
  const Hex = Source.GetValue<string>(Name);
  Result := HexToBytes(Hex);
end;

class function TTestSupport.HexToBytes(const Hex: string): TBytes;
begin
  const DigitCount = Length(Hex);
  if Odd(DigitCount) then
    raise ETestSupportError.CreateFmt(OddHexLength, [DigitCount]);

  SetLength(Result, DigitCount div HexDigitsPerByte);
  for var ByteIndex := 0 to High(Result) do
  begin
    const HighNibble = HexDigitValue(Hex[ByteIndex * HexDigitsPerByte + 1]);
    const LowNibble  = HexDigitValue(Hex[ByteIndex * HexDigitsPerByte + 2]);
    Result[ByteIndex] := (HighNibble * 16) + LowNibble;
  end;
end;

class function TTestSupport.HexDigitValue(const Digit: Char): Byte;
begin
  case Digit of
    '0'..'9' : Result := Ord(Digit) - Ord('0');
    'a'..'f' : Result := Ord(Digit) - Ord('a') + 10;
    'A'..'F' : Result := Ord(Digit) - Ord('A') + 10;
  else
    raise ETestSupportError.CreateFmt(InvalidHexDigit, [Digit]);
  end;
end;

class function TTestSupport.BytesToHex(const Bytes: TBytes): string;
begin
  const Builder = TStringBuilder.Create(Length(Bytes) * HexDigitsPerByte);
  try
    for var Value in Bytes do
    begin
      const UpperCaseDigits = IntToHex(Value, HexDigitsPerByte);
      Builder.Append(UpperCaseDigits.ToLower);
    end;
    Result := Builder.ToString;
  finally
    Builder.Free;
  end;
end;

class function TTestSupport.FlipBit(const Bytes: TBytes; const BitIndex: Integer): TBytes;
begin
  Result := Copy(Bytes);
  const ByteIndex = BitIndex div 8;
  const Mask: Byte = 1 shl (BitIndex mod 8);
  Result[ByteIndex] := Result[ByteIndex] xor Mask;
end;

class function TTestSupport.DerElement(const Tag: Byte; const Content: TBytes): TBytes;
begin
  const ContentLength = Length(Content);
  const UsesShortForm = (ContentLength < DerShortFormLimit);
  if UsesShortForm then
    Exit(TBytes.Create(Tag, Byte(ContentLength)) + Content);

  var LengthOctets: TBytes := nil;
  var Remaining := ContentLength;
  while Remaining > 0 do
  begin
    LengthOctets := TBytes.Create(Byte(Remaining and $FF)) + LengthOctets;
    Remaining    := Remaining shr 8;
  end;

  const LengthPrefix = Byte(DerLongFormFlag or Length(LengthOctets));
  Result := TBytes.Create(Tag, LengthPrefix) + LengthOctets + Content;
end;

class procedure TTestSupport.Log(const Text: string);
begin
  TDUnitX.CurrentRunner.Log(TLogLevel.Information, Text);
end;

end.
