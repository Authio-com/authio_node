import { createHash } from "node:crypto";
import { PRODUCTION_DENYLIST } from "./denylist.js";

/*
 * Environment isolation guard (AUT-93). Mirrors authio_go/platformsecrets.
 *
 * Outside production, a service must not be configured with a production
 * AWS resource or a production credential. bootstrapPlatformSecrets runs
 * this before fetching any secret and again over the values it loaded, and
 * throws on a match. In production the check is skipped entirely.
 *
 * The environment comes from RAILWAY_ENVIRONMENT_NAME, which the platform
 * injects and which cannot be copied between environments, then AUTHIO_ENV.
 * When neither is set (local dev) the check is skipped.
 *
 * AUTHIO_ENV_GUARD_WARN_ONLY lists variable names (comma separated, no
 * wildcards) whose matches are logged but do not block startup; use it only
 * while a known issue is being fixed. AUTHIO_ENV_GUARD_DENYLIST adds
 * denylist hashes (same format as denylist.ts).
 *
 * Logs carry variable names and the rule that matched, never values.
 */

const WARN_ONLY_VAR = "AUTHIO_ENV_GUARD_WARN_ONLY";
const DENYLIST_VAR = "AUTHIO_ENV_GUARD_DENYLIST";
const HASH_PREFIX = "authio-env-guard/v1\n";

const PRODUCTION_MARKER = /(^|[^a-z0-9])production([^a-z0-9]|$)/i;
const AWS_RESOURCE_NAME =
  /(SQS|QUEUE|BUCKET|KMS|(^|_)ARN(_|$)|CONFIG_SET|CONFIGURATION_SET|SNS|TOPIC|SECRET_IDS)/i;
const AWS_RESOURCE_VALUE =
  /^arn:aws[a-z-]*:|^s3:\/\/|^https:\/\/sqs\.|\.s3[.-]([a-z0-9-]+\.)*amazonaws\.com|\/\/s3[.-]([a-z0-9-]+\.)*amazonaws\.com\//i;

type Env = Record<string, string | undefined>;

export interface EnvViolation {
  name: string;
  rule: "production_resource" | "production_credential";
}

export function denylistDigest(value: string): string {
  return createHash("sha256").update(HASH_PREFIX + value).digest("hex");
}

function splitList(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

/** Returns the deployment environment and whether the guard applies. */
function environmentName(env: Env): [string, boolean] {
  const railway = (env.RAILWAY_ENVIRONMENT_NAME ?? "").trim().toLowerCase();
  const authio = (env.AUTHIO_ENV ?? "").trim().toLowerCase();
  const name = railway || authio;
  if (!name || name === "production") return [name, false];
  if (railway && authio === "production") {
    console.warn(
      JSON.stringify({
        msg: "platformsecrets.env_guard_env_mismatch",
        railway_environment: railway,
        authio_env: authio,
      }),
    );
  }
  return [name, true];
}

export function findViolations(
  vars: Env,
  extraDenylist: ReadonlySet<string> = new Set(),
): EnvViolation[] {
  const out: EnvViolation[] = [];
  for (const [name, value] of Object.entries(vars)) {
    if (
      !value ||
      name.startsWith("RAILWAY_") ||
      name === WARN_ONLY_VAR ||
      name === DENYLIST_VAR
    ) {
      continue;
    }
    if (
      (AWS_RESOURCE_NAME.test(name) || AWS_RESOURCE_VALUE.test(value)) &&
      PRODUCTION_MARKER.test(value)
    ) {
      out.push({ name, rule: "production_resource" });
      continue;
    }
    const digest = denylistDigest(value.trim());
    if (PRODUCTION_DENYLIST.has(digest) || extraDenylist.has(digest)) {
      out.push({ name, rule: "production_credential" });
    }
  }
  return out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/**
 * Throws when vars hold an enforced violation. The environment and the
 * guard's own settings are read from env. stage names the pass in logs.
 */
export function assertEnvironmentIsolation(
  vars: Env = process.env,
  stage = "config",
  env: Env = process.env,
): void {
  const [envName, applies] = environmentName(env);
  if (!applies) return;
  const warnOnly = splitList(env[WARN_ONLY_VAR]);
  const violations = findViolations(vars, splitList(env[DENYLIST_VAR]));

  const blocked: string[] = [];
  for (const v of violations) {
    const mode = warnOnly.has(v.name) ? "warn" : "enforce";
    if (mode === "enforce") blocked.push(v.name);
    console.error(
      JSON.stringify({
        msg: "platformsecrets.env_guard_violation",
        environment: envName,
        stage,
        var: v.name,
        rule: v.rule,
        mode,
      }),
    );
  }
  if (blocked.length > 0) {
    throw new Error(
      `platformsecrets: refusing to start in "${envName}": production-scoped values in ${blocked.join(", ")}`,
    );
  }
  console.log(
    JSON.stringify({
      msg: "platformsecrets.env_guard_ok",
      environment: envName,
      stage,
      vars_checked: Object.keys(vars).length,
      warnings: violations.length,
    }),
  );
}
