import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";

function parseIDs(raw: string | undefined): string[] {
  if (!raw?.trim()) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function mergeSecretJSON(payload: string): number {
  const kv = JSON.parse(payload) as Record<string, string>;
  let n = 0;
  for (const [k, v] of Object.entries(kv)) {
    if (!k || !v) continue;
    if (process.env[k]) continue;
    process.env[k] = v;
    n++;
  }
  return n;
}

export async function bootstrapPlatformSecrets(): Promise<void> {
  const ids = parseIDs(process.env.AUTHIO_AWS_SECRET_IDS);
  if (ids.length === 0) return;

  const region =
    process.env.AWS_REGION?.trim() ||
    process.env.AWS_DEFAULT_REGION?.trim() ||
    "us-east-1";

  const sm = new SecretsManagerClient({ region });
  let loaded = 0;
  for (const id of ids) {
    const out = await sm.send(
      new GetSecretValueCommand({ SecretId: id }),
    );
    if (!out.SecretString?.trim()) {
      throw new Error(`platformsecrets get ${id}: empty secret`);
    }
    loaded += mergeSecretJSON(out.SecretString);
  }

  console.log(
    JSON.stringify({
      msg: "platformsecrets.bootstrap_ok",
      secret_count: ids.length,
      env_keys_loaded: loaded,
    }),
  );
}
