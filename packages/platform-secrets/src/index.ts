import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { assertEnvironmentIsolation } from "./envguard.js";

export {
  assertEnvironmentIsolation,
  denylistDigest,
  findViolations,
  type EnvViolation,
} from "./envguard.js";

function parseIDs(raw: string | undefined): string[] {
  if (!raw?.trim()) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function mergeSecretJSON(
  payload: string,
  loaded: Record<string, string>,
): void {
  const kv = JSON.parse(payload) as Record<string, string>;
  for (const [k, v] of Object.entries(kv)) {
    if (!k || !v) continue;
    if (process.env[k]) continue;
    process.env[k] = v;
    loaded[k] = v;
  }
}

/**
 * Loads AUTHIO_AWS_SECRET_IDS into process.env. Outside production it also
 * throws when the configuration or the loaded secrets reference production
 * resources or credentials (see envguard.ts).
 */
export async function bootstrapPlatformSecrets(): Promise<void> {
  assertEnvironmentIsolation(process.env, "config");

  const ids = parseIDs(process.env.AUTHIO_AWS_SECRET_IDS);
  if (ids.length === 0) return;

  const region =
    process.env.AWS_REGION?.trim() ||
    process.env.AWS_DEFAULT_REGION?.trim() ||
    "us-east-1";

  const sm = new SecretsManagerClient({ region });
  const loaded: Record<string, string> = {};
  for (const id of ids) {
    const out = await sm.send(
      new GetSecretValueCommand({ SecretId: id }),
    );
    if (!out.SecretString?.trim()) {
      throw new Error(`platformsecrets get ${id}: empty secret`);
    }
    mergeSecretJSON(out.SecretString, loaded);
  }

  console.log(
    JSON.stringify({
      msg: "platformsecrets.bootstrap_ok",
      secret_count: ids.length,
      env_keys_loaded: Object.keys(loaded).length,
    }),
  );
  assertEnvironmentIsolation(loaded, "secrets");
}
