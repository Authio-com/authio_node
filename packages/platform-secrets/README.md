# @useauthio/platform-secrets

Bootstrap `process.env` from AWS Secrets Manager JSON bundles at Node/Next.js service startup.

## Usage

```ts
import { bootstrapPlatformSecrets } from "@useauthio/platform-secrets";

await bootstrapPlatformSecrets();
```

Set `AUTHIO_AWS_SECRET_IDS` to a comma-separated list of SM secret IDs. Existing env vars are never overwritten.

## Publish (required before consumer deploys)

Consumer repos depend on `^0.1.0` from npm. Publish after building:

```bash
cd packages/platform-secrets
pnpm build
npm publish --access public
```

Until published, Railway/CI builds of dashboard, admin, hosted-ui, etc. will fail `pnpm install`.
