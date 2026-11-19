unit Crypto4D.X509Limbo.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework;

type
  [TestFixture]
  TX509LimboTests = class
  private
    const
      SelectionFile   = 'x509-limbo/selection.json';
      PairsName       = 'pairs';
      CertificateName = 'certificate';
      FieldsFormat    = 'version %d, serial number %s, signature algorithm %s';
      PairTotal       = 52;
      SignedTotal     = 21;

    var
      FSelection: TJSONObject;

    function PairDescription(const Pair: TJSONObject; const Index: Integer): string;
    function ReferenceFields(const Pair: TJSONObject): string;
    function ParsedFields(const Pair: TJSONObject): string;
    function IsSignedByIssuer(const Pair: TJSONObject): Boolean;

  public
    [SetupFixture]
    procedure SetupFixture;

    [TearDownFixture]
    procedure TearDownFixture;

    [Test]
    procedure TryParse_SelectedCertificates_MatchReferenceFields;

    [Test]
    procedure IsSignedBy_SelectedPairs_MatchesReference;

    [Test]
    procedure TryParse_CertificateWithDuplicateExtension_ReturnsFalse;
  end;

implementation

uses
  Crypto4D.X509,
  Crypto4D.TestSupport;

procedure TX509LimboTests.SetupFixture;
begin
  FSelection := TTestSupport.LoadJsonObject(SelectionFile);
end;

procedure TX509LimboTests.TearDownFixture;
begin
  FSelection.Free;
end;

function TX509LimboTests.PairDescription(const Pair: TJSONObject; const Index: Integer): string;
begin
  const Testcase = Pair.GetValue<string>('testcase');
  Result := Format('pair %d (%s)', [Index, Testcase]);
end;

procedure TX509LimboTests.TryParse_SelectedCertificates_MatchReferenceFields;
begin
  const Pairs = TTestSupport.ArrayOf(FSelection, PairsName);

  for var Index := 0 to Pairs.Count - 1 do
  begin
    const Pair        = TTestSupport.ObjectAt(Pairs, Index);
    const Description = PairDescription(Pair, Index);
    const Expected    = ReferenceFields(Pair);
    const Actual      = ParsedFields(Pair);

    Assert.AreEqual(Expected, Actual, Description);
  end;

  Assert.AreEqual(PairTotal, Pairs.Count);
end;

function TX509LimboTests.ReferenceFields(const Pair: TJSONObject): string;
begin
  const Version   = Pair.GetValue<Integer>('version');
  const Serial    = Pair.GetValue<string>('serialNumber');
  const Algorithm = Pair.GetValue<string>('signatureAlgorithm');

  Result := Format(FieldsFormat, [Version, Serial, Algorithm]);
end;

function TX509LimboTests.ParsedFields(const Pair: TJSONObject): string;
begin
  const Der = TTestSupport.BytesOf(Pair, CertificateName);
  var Certificate: TX509CertificateInfo;
  if not TX509CertificateInfo.TryParse(Der, Certificate) then
    Exit('does not parse');

  const Serial = TTestSupport.BytesToHex(Certificate.SerialNumber);
  Result := Format(FieldsFormat, [Certificate.Version, Serial, Certificate.SignatureAlgorithm.Oid]);
end;

procedure TX509LimboTests.IsSignedBy_SelectedPairs_MatchesReference;
begin
  const Pairs = TTestSupport.ArrayOf(FSelection, PairsName);
  var Tally := Default(TVerificationTally);

  for var Index := 0 to Pairs.Count - 1 do
  begin
    const Pair        = TTestSupport.ObjectAt(Pairs, Index);
    const Description = PairDescription(Pair, Index);
    const Expected    = Pair.GetValue<Boolean>('signedByIssuer');
    const Verified    = IsSignedByIssuer(Pair);

    Tally.Add(Description, Expected, Verified);
  end;

  const Summary = Tally.Summary(SelectionFile);
  TTestSupport.Log(Summary);
  Assert.AreEqual('', Tally.MismatchList);
  Assert.AreEqual(SignedTotal, Tally.Verified, Summary);
end;

function TX509LimboTests.IsSignedByIssuer(const Pair: TJSONObject): Boolean;
begin
  const CertificateDer = TTestSupport.BytesOf(Pair, CertificateName);
  const IssuerDer      = TTestSupport.BytesOf(Pair, 'issuer');
  var Certificate: TX509CertificateInfo;
  var Issuer: TX509CertificateInfo;
  const BothParse = TX509CertificateInfo.TryParse(CertificateDer, Certificate) and
                    TX509CertificateInfo.TryParse(IssuerDer, Issuer);
  if not BothParse then
    Exit(False);

  Result := Certificate.IsSignedBy(Issuer.PublicKey);
end;

procedure TX509LimboTests.TryParse_CertificateWithDuplicateExtension_ReturnsFalse;
begin
  const Der = TTestSupport.BytesOf(FSelection, 'duplicateExtension.certificate');
  var Certificate: TX509CertificateInfo;

  const Parsed = TX509CertificateInfo.TryParse(Der, Certificate);

  Assert.IsFalse(Parsed);
end;

end.
