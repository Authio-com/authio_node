export class AuthioError extends Error {
  readonly code: string;
  readonly status: number;
  readonly requestId?: string;

  constructor(opts: {
    code: string;
    message: string;
    status: number;
    requestId?: string;
  }) {
    super(opts.message);
    this.name = "AuthioError";
    this.code = opts.code;
    this.status = opts.status;
    this.requestId = opts.requestId;
  }
}
