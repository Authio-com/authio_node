export { Authio, type AuthioOptions, hasFlag } from "./client";
export type {
  LocateVerifyInput,
  LocateVerifyResult,
  GenerateLinkInput,
  GenerateLinkResult,
  AuthioEvent,
  ListEventsInput,
  ListEventsResult,
  EvaluateFlagsInput,
  EvaluateFlagsResult,
} from "./client";
export { JwtVerifier, type AuthioClaims } from "./jwks";
export type {
  Session,
  SessionEnvelope,
  User,
  Organization,
  Membership,
  TokenResponse,
  ClientCredentialsInput,
} from "./types";
export { AuthioError } from "./errors";
