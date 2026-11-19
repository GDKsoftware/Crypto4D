unit Crypto4D.Errors;

interface

uses
  System.SysUtils;

type
  /// <summary>
  ///   Base class of every exception that Crypto4D raises.
  /// </summary>
  ECrypto4DError = class(Exception);

  /// <summary>
  ///   Raised when a caller passes a value that a function can never work with, such as a key of the wrong length.
  ///   Bad signatures and other bad input from outside do not raise; they make a verification return False.
  /// </summary>
  ECrypto4DArgumentError = class(ECrypto4DError);

  /// <summary>
  ///   Raised by TBigInteger for a division by zero, a subtraction with a negative result and a modular inverse
  ///   that does not exist.
  /// </summary>
  ECrypto4DArithmeticError = class(ECrypto4DError);

implementation

end.
