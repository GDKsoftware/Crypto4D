unit Crypto4D.Der.Tests;

interface

uses
  System.SysUtils,
  DUnitX.TestFramework,
  Crypto4D.Der;

type
  [TestFixture]
  TDerTests = class
  private
    function Bytes(const Hex: string): TBytes;
    function TryReadSingle(const Hex: string; out Element: TDerElement): Boolean;

  public
    [Test]
    procedure TryRead_ShortFormElement_ReturnsTagContentAndEncoding;

    [Test]
    procedure TryRead_LongFormElement_ReturnsContent;

    [Test]
    procedure TryRead_TwoElements_ReadsBothThenEnds;

    [Test]
    [TestCase('Empty', '')]
    [TestCase('TagOnly', '02')]
    [TestCase('ContentTooShort', '020201')]
    [TestCase('IndefiniteLength', '30800000')]
    [TestCase('ReservedLength', '02ff01')]
    [TestCase('LongFormForShortLength', '02810101')]
    [TestCase('LongFormWithLeadingZero', '0282008001')]
    [TestCase('LengthOctetsMissing', '0282')]
    [TestCase('FiveLengthOctets', '02850000000001ff')]
    [TestCase('HugeLength', '0284ffffffff01')]
    [TestCase('MultiByteTag', '1f0101')]
    procedure TryRead_MalformedElement_ReturnsFalse(const Hex: string);

    [Test]
    procedure TryReadTagged_OtherTag_ReturnsFalseAndKeepsPosition;

    [Test]
    procedure TryReadOnly_TrailingData_ReturnsFalse;

    [Test]
    [TestCase('Zero', '020100,00')]
    [TestCase('Small', '02017f,7f')]
    [TestCase('NeedsSignByte', '02020080,0080')]
    [TestCase('TwoBytes', '02020100,0100')]
    procedure TryGetUnsignedInteger_MinimalEncoding_ReturnsMagnitude(const Hex: string; const Expected: string);

    [Test]
    [TestCase('Empty', '0200')]
    [TestCase('Negative', '020180')]
    [TestCase('RedundantZero', '0202007f')]
    [TestCase('NotAnInteger', '040101')]
    procedure TryGetUnsignedInteger_InvalidEncoding_ReturnsFalse(const Hex: string);

    [Test]
    [TestCase('Sha256WithRsa', '06092a864886f70d01010b,1.2.840.113549.1.1.11')]
    [TestCase('Prime256v1', '06082a8648ce3d030107,1.2.840.10045.3.1.7')]
    [TestCase('Ed25519', '06032b6570,1.3.101.112')]
    [TestCase('FirstArcTwo', '0603883703,2.999.3')]
    [TestCase('FirstArcZero', '060100,0.0')]
    procedure TryGetObjectId_ValidEncoding_ReturnsDottedText(const Hex: string; const Expected: string);

    [Test]
    [TestCase('Empty', '0600')]
    [TestCase('EndsInsideArc', '06022a86')]
    [TestCase('PaddedArc', '06032a8001')]
    [TestCase('ArcTooLong', '060b2a8180808080808080807f')]
    [TestCase('NotAnObjectId', '04012a')]
    procedure TryGetObjectId_InvalidEncoding_ReturnsFalse(const Hex: string);

    [Test]
    procedure TryGetBitStringBytes_NoUnusedBits_ReturnsBytes;

    [Test]
    [TestCase('Empty', '0300')]
    [TestCase('UnusedBits', '030201ff')]
    [TestCase('NotABitString', '040200ff')]
    procedure TryGetBitStringBytes_InvalidEncoding_ReturnsFalse(const Hex: string);

    [Test]
    [TestCase('True', '0101ff,True,True')]
    [TestCase('False', '010100,True,False')]
    [TestCase('NotDer', '010101,False,False')]
    [TestCase('TwoBytes', '0102ffff,False,False')]
    procedure TryGetBoolean_Various_ReturnsExpected(const Hex: string; const ExpectedFound: Boolean; const ExpectedValue: Boolean);

    [Test]
    [TestCase('Null', '0500,True')]
    [TestCase('NullWithContent', '050100,False')]
    [TestCase('NotNull', '0400,False')]
    procedure IsNull_Various_ReturnsExpected(const Hex: string; const Expected: Boolean);
  end;

implementation

uses
  Crypto4D.TestSupport;

function TDerTests.Bytes(const Hex: string): TBytes;
begin
  Result := TTestSupport.HexToBytes(Hex);
end;

function TDerTests.TryReadSingle(const Hex: string; out Element: TDerElement): Boolean;
begin
  var Reader := TDerReader.Create(Bytes(Hex));
  Result := Reader.TryRead(Element);
end;

procedure TDerTests.TryRead_ShortFormElement_ReturnsTagContentAndEncoding;
begin
  var Element: TDerElement;

  const Found = TryReadSingle('0403010203', Element);

  Assert.IsTrue(Found);
  Assert.AreEqual(TDerTag.OctetString, Integer(Element.Tag));
  Assert.AreEqual('010203', TTestSupport.BytesToHex(Element.Content));
  Assert.AreEqual('0403010203', TTestSupport.BytesToHex(Element.Encoded));
end;

procedure TDerTests.TryRead_LongFormElement_ReturnsContent;
begin
  const ContentHex = string.Create('a', 400);
  var Element: TDerElement;

  const Found = TryReadSingle('0481c8' + ContentHex, Element);

  Assert.IsTrue(Found);
  Assert.AreEqual(ContentHex, TTestSupport.BytesToHex(Element.Content));
end;

procedure TDerTests.TryRead_TwoElements_ReadsBothThenEnds;
begin
  var Reader := TDerReader.Create(Bytes('0201050500'));
  var First: TDerElement;
  var Second: TDerElement;
  var Third: TDerElement;

  const FoundFirst  = Reader.TryRead(First);
  const FoundSecond = Reader.TryRead(Second);
  const FoundThird  = Reader.TryRead(Third);

  Assert.IsTrue(FoundFirst);
  Assert.IsTrue(FoundSecond);
  Assert.IsFalse(FoundThird);
  Assert.IsTrue(Second.IsNull);
  Assert.IsTrue(Reader.IsAtEnd);
end;

procedure TDerTests.TryRead_MalformedElement_ReturnsFalse(const Hex: string);
begin
  var Element: TDerElement;

  const Found = TryReadSingle(Hex, Element);

  Assert.IsFalse(Found);
end;

procedure TDerTests.TryReadTagged_OtherTag_ReturnsFalseAndKeepsPosition;
begin
  var Reader := TDerReader.Create(Bytes('020105'));
  var Element: TDerElement;

  const FoundSequence = Reader.TryReadTagged(TDerTag.Sequence, Element);
  const FoundInteger  = Reader.TryReadTagged(TDerTag.Integer, Element);

  Assert.IsFalse(FoundSequence);
  Assert.IsTrue(FoundInteger);
end;

procedure TDerTests.TryReadOnly_TrailingData_ReturnsFalse;
begin
  var Reader := TDerReader.Create(Bytes('02010500'));
  var Element: TDerElement;

  const Found = Reader.TryReadOnly(TDerTag.Integer, Element);

  Assert.IsFalse(Found);
end;

procedure TDerTests.TryGetUnsignedInteger_MinimalEncoding_ReturnsMagnitude(const Hex: string; const Expected: string);
begin
  var Element: TDerElement;
  var Magnitude: TBytes;
  TryReadSingle(Hex, Element);

  const Found = Element.TryGetUnsignedInteger(Magnitude);

  Assert.IsTrue(Found);
  Assert.AreEqual(Expected, TTestSupport.BytesToHex(Magnitude));
end;

procedure TDerTests.TryGetUnsignedInteger_InvalidEncoding_ReturnsFalse(const Hex: string);
begin
  var Element: TDerElement;
  var Magnitude: TBytes;
  TryReadSingle(Hex, Element);

  const Found = Element.TryGetUnsignedInteger(Magnitude);

  Assert.IsFalse(Found);
end;

procedure TDerTests.TryGetObjectId_ValidEncoding_ReturnsDottedText(const Hex: string; const Expected: string);
begin
  var Element: TDerElement;
  var DottedText: string;
  TryReadSingle(Hex, Element);

  const Found = Element.TryGetObjectId(DottedText);

  Assert.IsTrue(Found);
  Assert.AreEqual(Expected, DottedText);
end;

procedure TDerTests.TryGetObjectId_InvalidEncoding_ReturnsFalse(const Hex: string);
begin
  var Element: TDerElement;
  var DottedText: string;
  TryReadSingle(Hex, Element);

  const Found = Element.TryGetObjectId(DottedText);

  Assert.IsFalse(Found);
end;

procedure TDerTests.TryGetBitStringBytes_NoUnusedBits_ReturnsBytes;
begin
  var Element: TDerElement;
  var Content: TBytes;
  TryReadSingle('030300a1b2', Element);

  const Found = Element.TryGetBitStringBytes(Content);

  Assert.IsTrue(Found);
  Assert.AreEqual('a1b2', TTestSupport.BytesToHex(Content));
end;

procedure TDerTests.TryGetBitStringBytes_InvalidEncoding_ReturnsFalse(const Hex: string);
begin
  var Element: TDerElement;
  var Content: TBytes;
  TryReadSingle(Hex, Element);

  const Found = Element.TryGetBitStringBytes(Content);

  Assert.IsFalse(Found);
end;

procedure TDerTests.TryGetBoolean_Various_ReturnsExpected(const Hex: string; const ExpectedFound: Boolean; const ExpectedValue: Boolean);
begin
  var Element: TDerElement;
  var Value: Boolean;
  TryReadSingle(Hex, Element);

  const Found = Element.TryGetBoolean(Value);

  Assert.AreEqual(ExpectedFound, Found);
  Assert.AreEqual(ExpectedValue, Value);
end;

procedure TDerTests.IsNull_Various_ReturnsExpected(const Hex: string; const Expected: Boolean);
begin
  var Element: TDerElement;
  TryReadSingle(Hex, Element);

  Assert.AreEqual(Expected, Element.IsNull);
end;

end.
