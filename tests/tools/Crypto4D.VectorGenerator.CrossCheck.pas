unit Crypto4D.VectorGenerator.CrossCheck;

interface

uses
  System.SysUtils,
  System.JSON,
  Crypto4D.VectorGenerator.OpenSsl;

type
  ECrossCheckGeneratorError = class(Exception);

  {$SCOPEDENUMS ON}
  TSignatureFamily = (Ecdsa, Rsa, EdDsa);
  TMutation        = (None, Signature, SignatureDer, Message, Key);
  {$SCOPEDENUMS OFF}

  TMutationHelper = record helper for TMutation
    function Text: string;
  end;

  TKeyPlan = record
    Name: string;
    Family: TSignatureFamily;
    Algorithm: string;
    Option: string;
    KeyCount: Integer;
    CaseCount: Integer;
  end;

  TGeneratedKey = record
    Name: string;
    Family: TSignatureFamily;
    KeyFile: string;
    PublicKey: TBytes;
  end;

  TCasePlan = record
    KeyIndex: Integer;
    Message: TBytes;
    Mutation: TMutation;
    BitSeed: Cardinal;
  end;

  TGeneratedCase = record
    KeyIndex: Integer;
    Mutation: TMutation;
    Message: TBytes;
    Signature: TBytes;
    RawSignature: TBytes;
    PublicKey: TBytes;
    Verdict: TOpenSslVerdict;
  end;

  TCrossCheckGenerator = class
  private
    const
      MaxMessageBytes  = 200;
      P256ValueBytes   = 32;
      P256PointBytes   = 64;
      Ed25519KeyBytes  = 32;
      BitsPerByte      = 8;
      DerIntegerTag    = $02;
      DerSequenceTag   = $30;
      SignBit          = $80;

    var
      FTool: TOpenSslTool;
      FSeed: Integer;
      FKeys: TArray<TGeneratedKey>;
      FPlans: TArray<TCasePlan>;
      FCases: TArray<TGeneratedCase>;

    function KeyPlans: TArray<TKeyPlan>;
    function KeyPlan(const Name: string;
                     const Family: TSignatureFamily;
                     const Algorithm, Option: string;
                     const KeyCount, CaseCount: Integer): TKeyPlan;
    procedure PlanKeysAndCases(const Plan: TKeyPlan);
    function GenerateKey(const Plan: TKeyPlan): TGeneratedKey;
    function PlanCase(const Plan: TKeyPlan; const FirstKeyIndex: Integer): TCasePlan;
    function RandomMessage(const Family: TSignatureFamily): TBytes;
    function RandomMutation(const Family: TSignatureFamily): TMutation;
    function BuildCase(const Index: Integer): TGeneratedCase;
    procedure Mutate(const Family: TSignatureFamily; const BitSeed: Cardinal; var Generated: TGeneratedCase);
    function DamageKey(const Family: TSignatureFamily; const PublicKey: TBytes; const BitSeed: Cardinal): TBytes;
    function FindRsaModulus(const PublicKey: TBytes; out Offset, Count: Integer): Boolean;
    function FlipBit(const Bytes: TBytes; const Start, Count: Integer; const BitSeed: Cardinal): TBytes;
    function RawFromDer(const Signature: TBytes): TBytes;
    function DerFromRaw(const RawSignature: TBytes): TBytes;
    function DerInteger(const Magnitude: TBytes): TBytes;
    function WorkFile(const Name: string; const Index: Integer): string;
    function ToJson: TJSONObject;
    function CaseToJson(const Generated: TGeneratedCase): TJSONObject;
    function ToHex(const Bytes: TBytes): string;
    procedure PrintSummary;

  public
    constructor Create(const Tool: TOpenSslTool; const Seed: Integer);

    procedure Generate(const OutputFile: string);
  end;

implementation

uses
  System.IOUtils,
  System.Threading,
  Crypto4D.BigInteger,
  Crypto4D.Bytes,
  Crypto4D.Der,
  Crypto4D.Rsa,
  Crypto4D.X509;

resourcestring
  UnknownMutation       = 'Unknown mutation %d';
  OwnSignatureRejected  = 'OpenSSL did not verify its own signature in case %d: %s';
  UnreadableSignature   = 'OpenSSL wrote an ECDSA signature that is not a DER sequence of two integers';
  ModulusNotFound       = 'The RSA modulus was not found in the public key';

function TMutationHelper.Text: string;
begin
  case Self of
    TMutation.None         : Result := 'none';
    TMutation.Signature    : Result := 'signature';
    TMutation.SignatureDer : Result := 'signature-der';
    TMutation.Message      : Result := 'message';
    TMutation.Key          : Result := 'key';
  else
    raise ECrossCheckGeneratorError.CreateFmt(UnknownMutation, [Ord(Self)]);
  end;
end;

constructor TCrossCheckGenerator.Create(const Tool: TOpenSslTool; const Seed: Integer);
begin
  inherited Create;
  FTool := Tool;
  FSeed := Seed;
end;

procedure TCrossCheckGenerator.Generate(const OutputFile: string);
begin
  RandSeed := FSeed;
  FKeys    := nil;
  FPlans   := nil;
  for var Plan in KeyPlans do
  begin
    PlanKeysAndCases(Plan);
  end;

  SetLength(FCases, Length(FPlans));
  TParallel.For(0, High(FPlans),
    procedure(Index: Integer)
    begin
      FCases[Index] := BuildCase(Index);
    end);

  const Document = ToJson;
  try
    TFile.WriteAllText(OutputFile, Document.ToJSON, TEncoding.ASCII);
  finally
    Document.Free;
  end;

  PrintSummary;
end;

function TCrossCheckGenerator.KeyPlans: TArray<TKeyPlan>;
begin
  Result := [
    KeyPlan('ES256', TSignatureFamily.Ecdsa, 'EC', 'ec_paramgen_curve:P-256', 40, 1200),
    KeyPlan('RS256-2048', TSignatureFamily.Rsa, 'RSA', 'rsa_keygen_bits:2048', 10, 400),
    KeyPlan('RS256-3072', TSignatureFamily.Rsa, 'RSA', 'rsa_keygen_bits:3072', 6, 200),
    KeyPlan('RS256-4096', TSignatureFamily.Rsa, 'RSA', 'rsa_keygen_bits:4096', 4, 160),
    KeyPlan('EdDSA', TSignatureFamily.EdDsa, 'ED25519', '', 40, 1000)
  ];
end;

function TCrossCheckGenerator.KeyPlan(const Name: string;
                                      const Family: TSignatureFamily;
                                      const Algorithm, Option: string;
                                      const KeyCount, CaseCount: Integer): TKeyPlan;
begin
  Result.Name      := Name;
  Result.Family    := Family;
  Result.Algorithm := Algorithm;
  Result.Option    := Option;
  Result.KeyCount  := KeyCount;
  Result.CaseCount := CaseCount;
end;

procedure TCrossCheckGenerator.PlanKeysAndCases(const Plan: TKeyPlan);
begin
  const FirstKeyIndex = Length(FKeys);
  for var KeyNumber := 1 to Plan.KeyCount do
  begin
    FKeys := FKeys + [GenerateKey(Plan)];
  end;

  for var CaseNumber := 1 to Plan.CaseCount do
  begin
    FPlans := FPlans + [PlanCase(Plan, FirstKeyIndex)];
  end;
end;

function TCrossCheckGenerator.GenerateKey(const Plan: TKeyPlan): TGeneratedKey;
begin
  const KeyFile = WorkFile('key-%d.pem', Length(FKeys));
  FTool.GenerateKey(KeyFile, Plan.Algorithm, Plan.Option);

  Result.Name      := Plan.Name;
  Result.Family    := Plan.Family;
  Result.KeyFile   := KeyFile;
  Result.PublicKey := FTool.PublicKeyDer(KeyFile);
end;

function TCrossCheckGenerator.PlanCase(const Plan: TKeyPlan; const FirstKeyIndex: Integer): TCasePlan;
begin
  Result.KeyIndex := FirstKeyIndex + Random(Plan.KeyCount);
  Result.Message  := RandomMessage(Plan.Family);
  Result.Mutation := RandomMutation(Plan.Family);
  Result.BitSeed  := Cardinal(Random(MaxInt));
end;

function TCrossCheckGenerator.RandomMessage(const Family: TSignatureFamily): TBytes;
begin
  var ShortestMessage := 0;
  const CannotSignEmptyMessage = (Family = TSignatureFamily.EdDsa);
  if CannotSignEmptyMessage then
    ShortestMessage := 1;

  const MessageLength = ShortestMessage + Random(MaxMessageBytes + 1 - ShortestMessage);
  SetLength(Result, MessageLength);
  for var Index := 0 to MessageLength - 1 do
  begin
    Result[Index] := Byte(Random(256));
  end;
end;

function TCrossCheckGenerator.RandomMutation(const Family: TSignatureFamily): TMutation;
begin
  const StaysIntact = (Random(2) = 0);
  if StaysIntact then
    Exit(TMutation.None);

  var Choices: TArray<TMutation> := [TMutation.Signature, TMutation.Message, TMutation.Key];
  const HasDerSignature = (Family = TSignatureFamily.Ecdsa);
  if HasDerSignature then
    Choices := Choices + [TMutation.SignatureDer];

  Result := Choices[Random(Length(Choices))];
end;

function TCrossCheckGenerator.BuildCase(const Index: Integer): TGeneratedCase;
begin
  const Plan          = FPlans[Index];
  const Key           = FKeys[Plan.KeyIndex];
  const RawInput      = (Key.Family = TSignatureFamily.EdDsa);
  const MessageFile   = WorkFile('message-%d.bin', Index);
  const SignatureFile = WorkFile('signature-%d.bin', Index);
  const PublicKeyFile = WorkFile('public-%d.der', Index);

  TFile.WriteAllBytes(MessageFile, Plan.Message);
  FTool.Sign(Key.KeyFile, MessageFile, SignatureFile, RawInput);

  Result.KeyIndex     := Plan.KeyIndex;
  Result.Mutation     := Plan.Mutation;
  Result.Message      := Plan.Message;
  Result.Signature    := TFile.ReadAllBytes(SignatureFile);
  Result.RawSignature := nil;
  Result.PublicKey    := Key.PublicKey;
  Mutate(Key.Family, Plan.BitSeed, Result);

  TFile.WriteAllBytes(MessageFile, Result.Message);
  TFile.WriteAllBytes(SignatureFile, Result.Signature);
  TFile.WriteAllBytes(PublicKeyFile, Result.PublicKey);
  Result.Verdict := FTool.Verdict(PublicKeyFile, MessageFile, SignatureFile, RawInput);
  TFile.Delete(MessageFile);
  TFile.Delete(SignatureFile);
  TFile.Delete(PublicKeyFile);

  const OwnSignatureFailed = (Plan.Mutation = TMutation.None) and (Result.Verdict <> TOpenSslVerdict.Verified);
  if OwnSignatureFailed then
    raise ECrossCheckGeneratorError.CreateFmt(OwnSignatureRejected, [Index, Result.Verdict.Text]);
end;

procedure TCrossCheckGenerator.Mutate(const Family: TSignatureFamily; const BitSeed: Cardinal; var Generated: TGeneratedCase);
begin
  const IsEcdsa = (Family = TSignatureFamily.Ecdsa);
  if IsEcdsa then
    Generated.RawSignature := RawFromDer(Generated.Signature);

  case Generated.Mutation of
    TMutation.None:
      Exit;
    TMutation.Signature:
      if IsEcdsa then
      begin
        Generated.RawSignature := FlipBit(Generated.RawSignature, 0, Length(Generated.RawSignature), BitSeed);
        Generated.Signature    := DerFromRaw(Generated.RawSignature);
      end
      else
      begin
        Generated.Signature := FlipBit(Generated.Signature, 0, Length(Generated.Signature), BitSeed);
      end;
    TMutation.SignatureDer:
      begin
        Generated.Signature    := FlipBit(Generated.Signature, 0, Length(Generated.Signature), BitSeed);
        Generated.RawSignature := nil;
      end;
    TMutation.Message:
      if Length(Generated.Message) = 0 then
        Generated.Message := TBytes.Create(0)
      else
        Generated.Message := FlipBit(Generated.Message, 0, Length(Generated.Message), BitSeed);
    TMutation.Key:
      Generated.PublicKey := DamageKey(Family, Generated.PublicKey, BitSeed);
  else
    raise ECrossCheckGeneratorError.CreateFmt(UnknownMutation, [Ord(Generated.Mutation)]);
  end;
end;

function TCrossCheckGenerator.DamageKey(const Family: TSignatureFamily; const PublicKey: TBytes; const BitSeed: Cardinal): TBytes;
begin
  const KeyLength = Length(PublicKey);
  case Family of
    TSignatureFamily.Ecdsa:
      Result := FlipBit(PublicKey, KeyLength - P256PointBytes, P256PointBytes, BitSeed);
    TSignatureFamily.EdDsa:
      Result := FlipBit(PublicKey, KeyLength - Ed25519KeyBytes, Ed25519KeyBytes, BitSeed);
  else
    var Offset: Integer;
    var Count: Integer;
    if not FindRsaModulus(PublicKey, Offset, Count) then
      raise ECrossCheckGeneratorError.Create(ModulusNotFound);

    Result := FlipBit(PublicKey, Offset + 1, Count - 1, BitSeed);
  end;
end;

function TCrossCheckGenerator.FindRsaModulus(const PublicKey: TBytes; out Offset, Count: Integer): Boolean;
begin
  Offset := 0;
  Count  := 0;

  var KeyInfo: TX509PublicKeyInfo;
  var Key: TRsaPublicKey;
  const IsRsaKey = TX509PublicKeyInfo.TryParse(PublicKey, KeyInfo) and KeyInfo.TryGetRsaKey(Key);
  if not IsRsaKey then
    Exit(False);

  const Modulus   = TBigInteger.FromBytes(Key.Modulus);
  const Magnitude = Modulus.ToBytes;
  Count := Length(Magnitude);
  for var Start := 0 to Length(PublicKey) - Count do
  begin
    const Candidate = Copy(PublicKey, Start, Count);
    const IsModulus = TByteArrays.AreEqual(Candidate, Magnitude);
    if IsModulus then
    begin
      Offset := Start;
      Exit(True);
    end;
  end;

  Result := False;
end;

function TCrossCheckGenerator.FlipBit(const Bytes: TBytes; const Start, Count: Integer; const BitSeed: Cardinal): TBytes;
begin
  const BitCount: Cardinal = Cardinal(Count) * BitsPerByte;
  const BitOffset          = Integer(BitSeed mod BitCount);
  const ByteIndex          = Start + (BitOffset div BitsPerByte);
  const Mask: Byte         = 1 shl (BitOffset mod BitsPerByte);

  Result := Copy(Bytes);
  Result[ByteIndex] := Result[ByteIndex] xor Mask;
end;

function TCrossCheckGenerator.RawFromDer(const Signature: TBytes): TBytes;
begin
  var Outer := TDerReader.Create(Signature);
  var Sequence: TDerElement;
  var RElement: TDerElement;
  var SElement: TDerElement;
  var RBytes: TBytes;
  var SBytes: TBytes;

  var IsReadable := Outer.TryReadOnly(TDerTag.Sequence, Sequence);
  var Inner := TDerReader.Create(Sequence.Content);
  IsReadable := IsReadable and
                Inner.TryReadTagged(TDerTag.Integer, RElement) and
                Inner.TryReadOnly(TDerTag.Integer, SElement) and
                RElement.TryGetUnsignedInteger(RBytes) and
                SElement.TryGetUnsignedInteger(SBytes);
  if not IsReadable then
    raise ECrossCheckGeneratorError.Create(UnreadableSignature);

  const R = TBigInteger.FromBytes(RBytes);
  const S = TBigInteger.FromBytes(SBytes);
  Result := R.ToFixedBytes(P256ValueBytes) + S.ToFixedBytes(P256ValueBytes);
end;

function TCrossCheckGenerator.DerFromRaw(const RawSignature: TBytes): TBytes;
begin
  const RBytes = Copy(RawSignature, 0, P256ValueBytes);
  const SBytes = Copy(RawSignature, P256ValueBytes, P256ValueBytes);
  const Body   = DerInteger(RBytes) + DerInteger(SBytes);

  Result := TBytes.Create(DerSequenceTag, Byte(Length(Body))) + Body;
end;

function TCrossCheckGenerator.DerInteger(const Magnitude: TBytes): TBytes;
begin
  const Value   = TBigInteger.FromBytes(Magnitude);
  var Content   := Value.ToBytes;
  const IsNegativeAsWritten = ((Content[0] and SignBit) <> 0);
  if IsNegativeAsWritten then
    Content := TBytes.Create(0) + Content;

  Result := TBytes.Create(DerIntegerTag, Byte(Length(Content))) + Content;
end;

function TCrossCheckGenerator.WorkFile(const Name: string; const Index: Integer): string;
begin
  const FileName = Format(Name, [Index]);
  Result := TPath.Combine(FTool.WorkFolder, FileName);
end;

function TCrossCheckGenerator.ToJson: TJSONObject;
begin
  const Keys = TJSONArray.Create;
  for var Key in FKeys do
  begin
    const KeyObject = TJSONObject.Create;
    KeyObject.AddPair('algorithm', Key.Name);
    KeyObject.AddPair('publicKey', ToHex(Key.PublicKey));
    Keys.AddElement(KeyObject);
  end;

  const Cases = TJSONArray.Create;
  for var Generated in FCases do
  begin
    Cases.AddElement(CaseToJson(Generated));
  end;

  Result := TJSONObject.Create;
  Result.AddPair('generator', 'Crypto4D.VectorGenerator');
  Result.AddPair('openssl', FTool.Version);
  Result.AddPair('seed', TJSONNumber.Create(FSeed));
  Result.AddPair('keys', Keys);
  Result.AddPair('cases', Cases);
end;

function TCrossCheckGenerator.CaseToJson(const Generated: TGeneratedCase): TJSONObject;
begin
  const Key      = FKeys[Generated.KeyIndex];
  const Expected = (Generated.Verdict = TOpenSslVerdict.Verified);

  Result := TJSONObject.Create;
  Result.AddPair('algorithm', Key.Name);
  Result.AddPair('key', TJSONNumber.Create(Generated.KeyIndex));
  Result.AddPair('mutation', Generated.Mutation.Text);
  Result.AddPair('message', ToHex(Generated.Message));
  Result.AddPair('signature', ToHex(Generated.Signature));
  Result.AddPair('expected', TJSONBool.Create(Expected));
  Result.AddPair('opensslVerdict', Generated.Verdict.Text);

  const HasRawSignature = (Length(Generated.RawSignature) > 0);
  if HasRawSignature then
    Result.AddPair('rawSignature', ToHex(Generated.RawSignature));

  const HasDamagedKey = (Generated.Mutation = TMutation.Key);
  if HasDamagedKey then
    Result.AddPair('damagedKey', ToHex(Generated.PublicKey));
end;

function TCrossCheckGenerator.ToHex(const Bytes: TBytes): string;
begin
  const Builder = TStringBuilder.Create(Length(Bytes) * 2);
  try
    for var Value in Bytes do
    begin
      Builder.Append(IntToHex(Value, 2).ToLower);
    end;
    Result := Builder.ToString;
  finally
    Builder.Free;
  end;
end;

procedure TCrossCheckGenerator.PrintSummary;
begin
  for var Mutation := Low(TMutation) to High(TMutation) do
  begin
    for var Verdict := Low(TOpenSslVerdict) to High(TOpenSslVerdict) do
    begin
      var Count := 0;
      for var Generated in FCases do
      begin
        const IsCounted = (Generated.Mutation = Mutation) and (Generated.Verdict = Verdict);
        if IsCounted then
          Inc(Count);
      end;

      const HasCases = (Count > 0);
      if HasCases then
        System.Writeln(Format('%-14s %-22s %5d', [Mutation.Text, Verdict.Text, Count]));
    end;
  end;

  System.Writeln(Format('%d keys, %d cases', [Length(FKeys), Length(FCases)]));
end;

end.
