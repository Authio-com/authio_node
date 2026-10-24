# @useauthio/platform-secrets

Bootstrap `process.env` from AWS Secrets Manager JSON bundles at Node/Next.js service startup.

## Usage

```ts
import { bootstrapPlatformSecrets } from "@useauthio/platform-secrets";

await bootstrapPlatformSecrets();
```

Set `AUTHIO_AWS_SECRET_IDS` to a comma-separated list of SM secret IDs. Existing env vars are never overwritten.

## Environment isolation guard

Outside production, `bootstrapPlatformSecrets()` throws before fetching anything when the configuration (and again after loading, when the loaded secrets) contains:

- an AWS resource identifier (SQS queue, S3 bucket, KMS key, SES configuration set, ARN, secret ID) with a `production` marker, e.g. `authio-production-branding` or `authio-audit-events-production.fifo`;
- a value on the production denylist (production IAM access key ids, platform keys and KMS keys, stored as `sha256("authio-env-guard/v1\n" + value)` in `src/denylist.ts`).

The environment is `RAILWAY_ENVIRONMENT_NAME`, falling back to `AUTHIO_ENV`. In `production`, or when neither is set, the guard does nothing. Logs name the variable and the rule, never the value.

| Variable | Effect |
|---|---|
| `AUTHIO_ENV_GUARD_WARN_ONLY` | Comma-separated variable names whose matches are logged but don't block startup. For known issues being fixed only; no wildcards. |
| `AUTHIO_ENV_GUARD_DENYLIST` | Extra denylist hashes, comma-separated. |

Entrypoints that don't call `bootstrapPlatformSecrets()` can call `assertEnvironmentIsolation()` directly. The Go equivalent is `github.com/Authio-com/authio_go/platformsecrets`. Regenerate the denylist with `authio_infra/scripts/env-guard-denylist.py`.

## Publish (required before consumer deploys)

Consumer repos depend on `^0.1.0` from npm. Publish after building:

```bash
cd packages/platform-secrets
pnpm build
npm publish --access public
```

Until published, Railway/CI builds of dashboard, admin, hosted-ui, etc. will fail `pnpm install`.
