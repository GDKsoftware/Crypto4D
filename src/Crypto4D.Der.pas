unit Crypto4D.Der;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   Identifier octets of the ASN.1 types that Crypto4D reads.
  /// </summary>
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

  /// <summary>
  ///   One DER element: its tag, its content and its complete encoding.
  /// </summary>
  TDerElement = record
  private
    FTag: Byte;
    FContent: TBytes;
    FEncoded: TBytes;

    function TryDecodeArcs(out Arcs: TArray<UInt64>): Boolean;
    function FormatArcs(const Arcs: TArray<UInt64>): string;
    function HasMinimalIntegerContent: Boolean;

  public
    /// <summary>
    ///   Creates an element from parts that were already read. The arrays are not copied.
    /// </summary>
    /// <param name="Tag">Identifier octet.</param>
    /// <param name="Content">Content octets, without tag and length.</param>
    /// <param name="Encoded">Complete encoding: tag, length and content.</param>
    class function Create(const Tag: Byte; const Content, Encoded: TBytes): TDerElement; static;

    /// <summary>
    ///   Tells whether the element has a constructed context-specific tag.
    /// </summary>
    /// <param name="TagNumber">Tag number from 0 up to 30, as in [0] or [3].</param>
    /// <returns>True when the tag is the constructed context-specific tag with that number.</returns>
    function IsContextSpecific(const TagNumber: Byte): Boolean;

    /// <summary>
    ///   Returns the content of an INTEGER.
    /// </summary>
    /// <param name="TwosComplement">Receives the content: the value in two's complement, most significant byte
    ///   first. It can be negative.</param>
    /// <returns>False when the tag is not INTEGER, the content is empty or the encoding is not the shortest
    ///   one.</returns>
    function TryGetInteger(out TwosComplement: TBytes): Boolean;

    /// <summary>
    ///   Returns the content of an INTEGER that is zero or positive.
    /// </summary>
    /// <param name="Magnitude">Receives the value as big-endian bytes. A leading zero byte is present when the
    ///   encoding needs one to keep the value positive.</param>
    /// <returns>False when TryGetInteger would return False or the value is negative.</returns>
    function TryGetUnsignedInteger(out Magnitude: TBytes): Boolean;

    /// <summary>
    ///   Decodes an OBJECT IDENTIFIER.
    /// </summary>
    /// <param name="DottedText">Receives the identifier in dotted notation, such as 1.2.840.10045.2.1.</param>
    /// <returns>False when the tag is not OBJECT IDENTIFIER, the content is empty, an arc is not in its shortest
    ///   encoding or an arc is longer than 9 bytes.</returns>
    function TryGetObjectId(out DottedText: string): Boolean;

    /// <summary>
    ///   Returns the bytes of a BIT STRING that holds whole bytes.
    /// </summary>
    /// <param name="Bytes">Receives the content without the leading count of unused bits.</param>
    /// <returns>False when the tag is not BIT STRING, the content is empty or the count of unused bits is not
    ///   zero.</returns>
    function TryGetBitStringBytes(out Bytes: TBytes): Boolean;

    /// <summary>
    ///   Tells whether the content is a valid DER encoding of a bit string, whatever the tag. Use it for an
    ///   implicitly tagged BIT STRING.
    /// </summary>
    /// <returns>False when the content is empty, the count of unused bits is above 7, unused bits are announced
    ///   without data, or an unused bit is set.</returns>
    function HasBitStringContent: Boolean;

    /// <summary>
    ///   Decodes a BOOLEAN.
    /// </summary>
    /// <param name="Value">Receives True for the content FF and False otherwise.</param>
    /// <returns>False when the tag is not BOOLEAN or the content is not exactly one byte with the value 00 or
    ///   FF.</returns>
    function TryGetBoolean(out Value: Boolean): Boolean;

    /// <summary>
    ///   True when the element is a NULL without content.
    /// </summary>
    function IsNull: Boolean;

    /// <summary>
    ///   Identifier octet of the element.
    /// </summary>
    property Tag: Byte read FTag;

    /// <summary>
    ///   Content octets, without tag and length.
    /// </summary>
    property Content: TBytes read FContent;

    /// <summary>
    ///   Complete encoding of the element: tag, length and content.
    /// </summary>
    property Encoded: TBytes read FEncoded;
  end;

  /// <summary>
  ///   Reads the DER elements in a byte array one after another. The reader is strict: it accepts single-byte tags
  ///   only and a definite length in the shortest encoding of at most four length octets. It does not look inside
  ///   the content of an element; create another reader on the content for that.
  /// </summary>
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
    /// <summary>
    ///   Creates a reader at the first byte of Data. The array is not copied.
    /// </summary>
    /// <param name="Data">Bytes that hold zero or more DER elements.</param>
    class function Create(const Data: TBytes): TDerReader; static;

    /// <summary>
    ///   True when every byte has been read.
    /// </summary>
    function IsAtEnd: Boolean;

    /// <summary>
    ///   Returns the tag of the next element without reading it.
    /// </summary>
    /// <param name="Tag">Receives the identifier octet, or 0 at the end of the data.</param>
    /// <returns>False at the end of the data.</returns>
    function TryPeekTag(out Tag: Byte): Boolean;

    /// <summary>
    ///   Reads the next element and moves past it.
    /// </summary>
    /// <param name="Element">Receives the element. Its content and encoding are copies.</param>
    /// <returns>False at the end of the data, for a multi-byte tag, for a length that is indefinite, not in its
    ///   shortest encoding or longer than four octets, and when the data ends before the content does. The position
    ///   does not change then.</returns>
    function TryRead(out Element: TDerElement): Boolean;

    /// <summary>
    ///   Reads the next element when it has the expected tag.
    /// </summary>
    /// <param name="ExpectedTag">Identifier octet the element must have.</param>
    /// <param name="Element">Receives the element.</param>
    /// <returns>False when the next element has another tag or TryRead would return False. The position does not
    ///   change then.</returns>
    function TryReadTagged(const ExpectedTag: Byte; out Element: TDerElement): Boolean;

    /// <summary>
    ///   Reads the next element when it has the expected tag and is the last one in the data.
    /// </summary>
    /// <param name="ExpectedTag">Identifier octet the element must have.</param>
    /// <param name="Element">Receives the element.</param>
    /// <returns>False when TryReadTagged would return False or bytes follow the element.</returns>
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
  ArcSeparator         = '.';
  SignBit              = $80;
  RedundantZero        = $00;
  RedundantOnes        = $FF;
  MaxUnusedBits        = 7;
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

function TDerElement.TryGetInteger(out TwosComplement: TBytes): Boolean;
begin
  TwosComplement := nil;
  const IsInteger = (FTag = TDerTag.Integer) and HasMinimalIntegerContent;
  if not IsInteger then
    Exit(False);

  TwosComplement := FContent;
  Result         := True;
end;

function TDerElement.HasMinimalIntegerContent: Boolean;
begin
  const ContentLength = Length(FContent);
  const IsEmpty       = (ContentLength = 0);
  if IsEmpty then
    Exit(False);

  const HasSingleByte = (ContentLength = 1);
  if HasSingleByte then
    Exit(True);

  const NextIsNegative   = ((FContent[1] and SignBit) <> 0);
  const HasRedundantZero = (FContent[0] = RedundantZero) and not NextIsNegative;
  const HasRedundantOnes = (FContent[0] = RedundantOnes) and NextIsNegative;
  Result := not (HasRedundantZero or HasRedundantOnes);
end;

function TDerElement.TryGetUnsignedInteger(out Magnitude: TBytes): Boolean;
begin
  Magnitude := nil;

  var TwosComplement: TBytes;
  if not TryGetInteger(TwosComplement) then
    Exit(False);

  const IsNegative = ((TwosComplement[0] and SignBit) <> 0);
  if IsNegative then
    Exit(False);

  Magnitude := TwosComplement;
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
  var Decoded: TArray<UInt64>;
  SetLength(Decoded, Length(FContent));
  var ArcCount := 0;
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
      Decoded[ArcCount] := Arc;
      Inc(ArcCount);
      Arc      := 0;
      ArcBytes := 0;
    end;
  end;

  const EndsOnArcBoundary = (ArcBytes = 0);
  const IsComplete        = EndsOnArcBoundary and (ArcCount > 0);
  if not IsComplete then
    Exit(False);

  Arcs   := Copy(Decoded, 0, ArcCount);
  Result := True;
end;

function TDerElement.FormatArcs(const Arcs: TArray<UInt64>): string;
begin
  const Combined = Arcs[0];
  var FirstArc: UInt64 := Combined div FirstArcMultiplier;
  const IsAboveLastRoot = (FirstArc > MaxFirstArc);
  if IsAboveLastRoot then
    FirstArc := MaxFirstArc;
  const SecondArc = Combined - (FirstArc * FirstArcMultiplier);

  const Builder = TStringBuilder.Create;
  try
    Builder.Append(FirstArc);
    Builder.Append(ArcSeparator);
    Builder.Append(SecondArc);
    for var Index := 1 to High(Arcs) do
    begin
      Builder.Append(ArcSeparator);
      Builder.Append(Arcs[Index]);
    end;

    Result := Builder.ToString;
  finally
    Builder.Free;
  end;
end;

function TDerElement.TryGetBitStringBytes(out Bytes: TBytes): Boolean;
begin
  Bytes := nil;
  const IsBitString = (FTag = TDerTag.BitString) and HasBitStringContent;
  if not IsBitString then
    Exit(False);

  const HasUnusedBits = (FContent[0] <> 0);
  if HasUnusedBits then
    Exit(False);

  Bytes  := Copy(FContent, 1, Length(FContent) - 1);
  Result := True;
end;

function TDerElement.HasBitStringContent: Boolean;
begin
  const ContentLength = Length(FContent);
  const IsEmpty       = (ContentLength = 0);
  if IsEmpty then
    Exit(False);

  const UnusedBits   = FContent[0];
  const HasNoData    = (ContentLength = 1);
  const IsImpossible = (UnusedBits > MaxUnusedBits) or (HasNoData and (UnusedBits > 0));
  if IsImpossible then
    Exit(False);

  const UnusedMask: Byte = (1 shl UnusedBits) - 1;
  const LastByte         = FContent[ContentLength - 1];
  Result := ((LastByte and UnusedMask) = 0);
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
