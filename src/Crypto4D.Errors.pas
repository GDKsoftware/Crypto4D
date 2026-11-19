unit Crypto4D.Errors;

interface

uses
  System.SysUtils;

type
  ECrypto4DError = class(Exception);

  ECrypto4DArgumentError = class(ECrypto4DError);

  ECrypto4DArithmeticError = class(ECrypto4DError);

implementation

end.
