unit Crypto4D.NistCavp.Tests;

interface

uses
  System.SysUtils,
  System.JSON,
  DUnitX.TestFramework;

type
  TNistCavpVerifier = reference to function(const Test: TJSONObject): Boolean;

  [TestFixture]
  TNistCavpTests = class
  private
    const
      EcdsaFile     = 'nist-cavp/ecdsa_p256_sha256_sigver.json';
      EcdsaTotal    = 15;
      EcdsaPassing  = 3;
      RsaFile       = 'nist-cavp/rsa_pkcs1_sha256_sigver.json';
      RsaTotal      = 35;
      RsaPassing    = 6;
      PassPrefix    = 'P';
      MessageName   = 'message';

    procedure CheckFile(const FileName: string;
                        const ExpectedTotal, ExpectedPassing: Integer;
                        const Verifier: TNistCavpVerifier);
    function VerifyEcdsa(const Test: TJSONObject): Boolean;
    function VerifyRsa(const Test: TJSONObject): Boolean;

  public
    [Test]
    procedure EcdsaP256Sha256_SigVer_MatchesResults;

    [Test]
    procedure RsaPkcs1Sha256_SigVer_MatchesResults;
  end;

implementation

uses
  Crypto4D.Ecdsa,
  Crypto4D.Rsa,
  Crypto4D.TestSupport;

procedure TNistCavpTests.EcdsaP256Sha256_SigVer_MatchesResults;
begin
  CheckFile(EcdsaFile, EcdsaTotal, EcdsaPassing, VerifyEcdsa);
end;

procedure TNistCavpTests.RsaPkcs1Sha256_SigVer_MatchesResults;
begin
  CheckFile(RsaFile, RsaTotal, RsaPassing, VerifyRsa);
end;

procedure TNistCavpTests.CheckFile(const FileName: string;
                                   const ExpectedTotal, ExpectedPassing: Integer;
                                   const Verifier: TNistCavpVerifier);
begin
  const Document = TTestSupport.LoadJsonObject(FileName);
  try
    const Tests = TTestSupport.ArrayOf(Document, 'tests');
    var Tally := Default(TVerificationTally);
    for var Index := 0 to Tests.Count - 1 do
    begin
      const Test        = TTestSupport.ObjectAt(Tests, Index);
      const Outcome     = Test.GetValue<string>('result');
      const Description = Format('test %d (%s)', [Index, Outcome]);
      const Expected    = Outcome.StartsWith(PassPrefix);
      const Verified    = Verifier(Test);

      Tally.Add(Description, Expected, Verified);
    end;

    const Summary = Tally.Summary(FileName);
    TTestSupport.Log(Summary);
    Assert.AreEqual(ExpectedTotal, Tally.Total, Summary);
    Assert.AreEqual('', Tally.MismatchList);
    Assert.AreEqual(ExpectedPassing, Tally.Verified, Summary);
  finally
    Document.Free;
  end;
end;

function TNistCavpTests.VerifyEcdsa(const Test: TJSONObject): Boolean;
begin
  const X       = TTestSupport.BytesOf(Test, 'qx');
  const Y       = TTestSupport.BytesOf(Test, 'qy');
  const Message = TTestSupport.BytesOf(Test, MessageName);
  const R       = TTestSupport.BytesOf(Test, 'r');
  const S       = TTestSupport.BytesOf(Test, 's');
  const Key     = TEcdsaP256PublicKey.FromCoordinates(X, Y);

  Result := TEcdsaP256.VerifyRaw(Key, Message, R + S);
end;

function TNistCavpTests.VerifyRsa(const Test: TJSONObject): Boolean;
begin
  const Modulus   = TTestSupport.BytesOf(Test, 'modulus');
  const Exponent  = TTestSupport.BytesOf(Test, 'exponent');
  const Message   = TTestSupport.BytesOf(Test, MessageName);
  const Signature = TTestSupport.BytesOf(Test, 'signature');
  const Key       = TRsaPublicKey.Create(Modulus, Exponent);

  Result := TRsaPkcs1Sha256.Verify(Key, Message, Signature);
end;

end.
