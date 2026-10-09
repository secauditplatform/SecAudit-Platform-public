/** Thrown by loginLocal when the API requires a TOTP / recovery code step. */
export class MfaRequiredError extends Error {
  readonly mfaToken: string;
  readonly username: string;

  constructor(mfaToken: string, username: string) {
    super("MFA_REQUIRED");
    this.name = "MfaRequiredError";
    this.mfaToken = mfaToken;
    this.username = username;
  }
}
