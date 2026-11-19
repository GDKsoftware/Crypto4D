unit Crypto4D.Der;

interface

uses
  System.SysUtils;

type
  TDerTag = record
  public
    const
      Boolean         = $01;
      Integer         = $02;
      BitString       = $03;
      OctetString     = $04;
      Null            = $05;
      ObjectId        = $06;
      Sequence        = $30;
      ContextSpecific = $80;
      Constructed     = $20;
  end;

  TDerElement = record
  private
    FTag: Byte;
    FContent: TBytes;
    FEncoded: TBytes;

    function TryDecodeArcs(out Arcs: TArray<UInt64>): Boolean;
    function FormatArcs(const Arcs: TArray<UInt64>): string;

  public
    class function Create(const Tag: Byte; const Content, Encoded: TBytes): TDerElement; static;

    function IsContextSpecific(const TagNumber: Byte): Boolean;
    function TryGetUnsignedInteger(out Magnitude: TBytes): Boolean;
    function TryGetObjectId(out DottedText: string): Boolean;
    function TryGetBitStringBytes(out Bytes: TBytes): Boolean;
    function TryGetBoolean(out Value: Boolean): Boolean;
    function IsNull: Boolean;

    property Tag: Byte read FTag;
    property Content: TBytes read FContent;
    property Encoded: TBytes read FEncoded;
  end;

  TDerReader = record
  private
    const
      LongFormFlag        = $80;
      LengthMask          = $7F;
      MultiByteTagNumber  = $1F;
      MaxLengthOctets     = 4;
      ShortFormLimit      = $80;

    var
      FData: TBytes;
      FPosition: Integer;

    function TryReadLength(const LengthPosition: Integer; out ContentLength: Int64; out ContentPosition: Integer): Boolean;

  public
    class function Create(const Data: TBytes): TDerReader; static;

    function IsAtEnd: Boolean;
    function TryPeekTag(out Tag: Byte): Boolean;
    function TryRead(out Element: TDerElement): Boolean;
    function TryReadTagged(const ExpectedTag: Byte; out Element: TDerElement): Boolean;
    function TryReadOnly(const ExpectedTag: Byte; out Element: TDerElement): Boolean;
  end;

implementation

const
  BitsPerArcByte       = 7;
  ArcContinuationFlag  = $80;
  ArcValueMask         = $7F;
  MaxArcBytes          = 9;
  FirstArcMultiplier   = 40;
  MaxFirstArc          = 2;
  SignBit              = $80;
  BooleanTrue          = $FF;
  BooleanFalse         = $00;

class function TDerElement.Create(const Tag: Byte; const Content, Encoded: TBytes): TDerElement;
begin
  Result.FTag     := Tag;
  Result.FContent := Content;
  Result.FEncoded := Encoded;
end;

function TDerElement.IsContextSpecific(const TagNumber: Byte): Boolean;
begin
  const ExpectedTag = TDerTag.ContextSpecific or TDerTag.Constructed or TagNumber;
  Result := (FTag = ExpectedTag);
end;

function TDerElement.TryGetUnsignedInteger(out Magnitude: TBytes): Boolean;
begin
  Magnitude := nil;
  const ContentLength = Length(FContent);
  const IsInteger     = (FTag = TDerTag.Integer) and (ContentLength > 0);
  if not IsInteger then
    Exit(False);

  const IsNegative = ((FContent[0] and SignBit) <> 0);
  if IsNegative then
    Exit(False);

  const HasRedundantLeadingZero = (ContentLength > 1) and
                                  (FContent[0] = 0) and
                                  ((FContent[1] and SignBit) = 0);
  if HasRedundantLeadingZero then
    Exit(False);

  Magnitude := FContent;
  Result    := True;
end;

function TDerElement.TryGetObjectId(out DottedText: string): Boolean;
begin
  DottedText := '';

  var Arcs: TArray<UInt64>;
  const IsObjectId = (FTag = TDerTag.ObjectId) and TryDecodeArcs(Arcs);
  if not IsObjectId then
    Exit(False);

  DottedText := FormatArcs(Arcs);
  Result     := True;
end;

function TDerElement.TryDecodeArcs(out Arcs: TArray<UInt64>): Boolean;
begin
  Arcs := nil;
  var Arc: UInt64 := 0;
  var ArcBytes := 0;

  for var Value in FContent do
  begin
    const StartsWithPadding = (ArcBytes = 0) and (Value = ArcContinuationFlag);
    const IsTooLong         = (ArcBytes = MaxArcBytes);
    if StartsWithPadding or IsTooLong then
      Exit(False);

    Arc := (Arc shl BitsPerArcByte) or (Value and ArcValueMask);
    Inc(ArcBytes);

    const ArcIsComplete = ((Value and ArcContinuationFlag) = 0);
    if ArcIsComplete then
    begin
      Arcs     := Arcs + [Arc];
      Arc      := 0;
      ArcBytes := 0;
    end;
  end;

  const EndsOnArcBoundary = (ArcBytes = 0);
  Result := EndsOnArcBoundary and (Length(Arcs) > 0);
end;

function TDerElement.FormatArcs(const Arcs: TArray<UInt64>): string;
begin
  const Combined = Arcs[0];
  var FirstArc: UInt64 := Combined div FirstArcMultiplier;
  const IsAboveLastRoot = (FirstArc > MaxFirstArc);
  if IsAboveLastRoot then
    FirstArc := MaxFirstArc;
  const SecondArc = Combined - (FirstArc * FirstArcMultiplier);

  Result := Format('%d.%d', [FirstArc, SecondArc]);
  for var Index := 1 to High(Arcs) do
  begin
    Result := Format('%s.%d', [Result, Arcs[Index]]);
  end;
end;

function TDerElement.TryGetBitStringBytes(out Bytes: TBytes): Boolean;
begin
  Bytes := nil;
  const IsBitString = (FTag = TDerTag.BitString) and (Length(FContent) > 0);
  if not IsBitString then
    Exit(False);

  const HasUnusedBits = (FContent[0] <> 0);
  if HasUnusedBits then
    Exit(False);

  Bytes  := Copy(FContent, 1, Length(FContent) - 1);
  Result := True;
end;

function TDerElement.TryGetBoolean(out Value: Boolean): Boolean;
begin
  Value := False;
  const IsBoolean = (FTag = TDerTag.Boolean) and (Length(FContent) = 1);
  if not IsBoolean then
    Exit(False);

  const Encoding = FContent[0];
  Value  := (Encoding = BooleanTrue);
  Result := (Encoding = BooleanTrue) or (Encoding = BooleanFalse);
end;

function TDerElement.IsNull: Boolean;
begin
  Result := (FTag = TDerTag.Null) and (Length(FContent) = 0);
end;

class function TDerReader.Create(const Data: TBytes): TDerReader;
begin
  Result.FData     := Data;
  Result.FPosition := 0;
end;

function TDerReader.IsAtEnd: Boolean;
begin
  Result := (FPosition >= Length(FData));
end;

function TDerReader.TryPeekTag(out Tag: Byte): Boolean;
begin
  Tag    := 0;
  Result := not IsAtEnd;
  if Result then
    Tag := FData[FPosition];
end;

function TDerReader.TryRead(out Element: TDerElement): Boolean;
begin
  Element := Default(TDerElement);

  var Tag: Byte;
  if not TryPeekTag(Tag) then
    Exit(False);

  const HasMultiByteTag = ((Tag and MultiByteTagNumber) = MultiByteTagNumber);
  if HasMultiByteTag then
    Exit(False);

  var ContentLength: Int64;
  var ContentPosition: Integer;
  if not TryReadLength(FPosition + 1, ContentLength, ContentPosition) then
    Exit(False);

  const Remaining: Int64 = Int64(Length(FData)) - ContentPosition;
  const IsTruncated      = (ContentLength > Remaining);
  if IsTruncated then
    Exit(False);

  const ContentSize = Integer(ContentLength);
  const EndPosition = ContentPosition + ContentSize;
  const Content     = Copy(FData, ContentPosition, ContentSize);
  const Encoded     = Copy(FData, FPosition, EndPosition - FPosition);

  Element   := TDerElement.Create(Tag, Content, Encoded);
  FPosition := EndPosition;
  Result    := True;
end;

function TDerReader.TryReadLength(const LengthPosition: Integer; out ContentLength: Int64; out ContentPosition: Integer): Boolean;
begin
  ContentLength   := 0;
  ContentPosition := 0;
  const DataLength   = Length(FData);
  const IsPastTheEnd = (LengthPosition >= DataLength);
  if IsPastTheEnd then
    Exit(False);

  const FirstOctet = FData[LengthPosition];
  const IsShortForm = (FirstOctet < ShortFormLimit);
  if IsShortForm then
  begin
    ContentLength   := FirstOctet;
    ContentPosition := LengthPosition + 1;
    Exit(True);
  end;

  const OctetCount     = FirstOctet and LengthMask;
  const LastOctetIndex = Int64(LengthPosition) + OctetCount;
  const IsReadable     = (OctetCount >= 1) and
                         (OctetCount <= MaxLengthOctets) and
                         (LastOctetIndex < DataLength);
  if not IsReadable then
    Exit(False);

  const HasLeadingZero = (FData[LengthPosition + 1] = 0);
  if HasLeadingZero then
    Exit(False);

  for var Index := LengthPosition + 1 to LengthPosition + OctetCount do
  begin
    ContentLength := (ContentLength shl 8) or FData[Index];
  end;

  const FitsShortForm = (ContentLength < ShortFormLimit);
  if FitsShortForm then
    Exit(False);

  ContentPosition := LengthPosition + OctetCount + 1;
  Result          := True;
end;

function TDerReader.TryReadTagged(const ExpectedTag: Byte; out Element: TDerElement): Boolean;
begin
  Element := Default(TDerElement);

  var Tag: Byte;
  const HasExpectedTag = TryPeekTag(Tag) and (Tag = ExpectedTag);
  if not HasExpectedTag then
    Exit(False);

  Result := TryRead(Element);
end;

function TDerReader.TryReadOnly(const ExpectedTag: Byte; out Element: TDerElement): Boolean;
begin
  Result := TryReadTagged(ExpectedTag, Element) and IsAtEnd;
end;

end.
