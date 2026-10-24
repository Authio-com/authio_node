import { afterEach, describe, expect, it, vi } from "vitest";
import { PRODUCTION_DENYLIST } from "../src/denylist";
import {
  assertEnvironmentIsolation,
  denylistDigest,
  findViolations,
} from "../src/envguard";

// Shared with the Go implementation's tests.
const EXAMPLE_KEY_ID = "AKIAEXAMPLEEXAMPLE00";
const EXAMPLE_DIGEST =
  "86041fb2a0bbc6c0d6cb70abe7d9173e15c2f4637b8881094da52b2be9899b43";

afterEach(() => {
  vi.restoreAllMocks();
});

function quiet() {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  return vi.spyOn(console, "error").mockImplementation(() => {});
}

describe("denylistDigest", () => {
  it("matches the Go implementation", () => {
    expect(denylistDigest(EXAMPLE_KEY_ID)).toBe(EXAMPLE_DIGEST);
  });

  it("ships lowercase sha256 entries", () => {
    expect(PRODUCTION_DENYLIST.size).toBeGreaterThan(0);
    for (const h of PRODUCTION_DENYLIST) expect(h).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("findViolations", () => {
  it("flags production resources and denylisted credentials only", () => {
    const got = findViolations(
      {
        AUDIT_SQS_QUEUE_URL:
          "https://sqs.us-east-1.amazonaws.com/123456789012/authio-audit-events-production.fifo",
        AUTHIO_BRANDING_BUCKET: "authio-production-branding",
        AUTHIO_KMS_KEY_ID: "alias/authio-production-envelope",
        AUTHIO_AWS_SECRET_IDS:
          "authio/e2e/platform/internal,authio/production/platform/project-keys",
        STATUS_SNAPSHOT_URL:
          "https://authio-production-status-snapshot.s3.us-east-1.amazonaws.com/status/snapshot.json",
        SES_CONFIG_SET: "authio-production-events",
        AWS_ACCESS_KEY_ID: EXAMPLE_KEY_ID,
        OK_QUEUE_URL:
          "https://sqs.us-east-1.amazonaws.com/123456789012/authio-audit-events-e2e.fifo",
        OK_BUCKET: "authio-e2e-branding",
        OK_STAGING: "authio-staging-validation-audit-immutable",
        NODE_ENV: "production",
        SENTRY_ENVIRONMENT: "production",
        ALERT_WARN_LEVEL: "production",
        AUTHIO_PUBLIC_URL: "https://production.example.com",
        RAILWAY_SERVICE_NAME: "authio-production-thing",
        EMPTY_BUCKET: "",
      },
      new Set([EXAMPLE_DIGEST]),
    );
    expect(got).toEqual([
      { name: "AUDIT_SQS_QUEUE_URL", rule: "production_resource" },
      { name: "AUTHIO_AWS_SECRET_IDS", rule: "production_resource" },
      { name: "AUTHIO_BRANDING_BUCKET", rule: "production_resource" },
      { name: "AUTHIO_KMS_KEY_ID", rule: "production_resource" },
      { name: "AWS_ACCESS_KEY_ID", rule: "production_credential" },
      { name: "SES_CONFIG_SET", rule: "production_resource" },
      { name: "STATUS_SNAPSHOT_URL", rule: "production_resource" },
    ]);
  });
});

describe("assertEnvironmentIsolation", () => {
  const bad = {
    AUTHIO_BRANDING_BUCKET: "authio-production-branding",
    AWS_ACCESS_KEY_ID: EXAMPLE_KEY_ID,
  };

  it.each([
    ["production", undefined],
    ["production", "e2e"],
    [undefined, "production"],
    [undefined, undefined],
  ])("skips railway=%s authio=%s", (railway, authio) => {
    quiet();
    expect(() =>
      assertEnvironmentIsolation(bad, "config", {
        RAILWAY_ENVIRONMENT_NAME: railway,
        AUTHIO_ENV: authio,
      }),
    ).not.toThrow();
  });

  it.each([
    ["e2e", undefined],
    ["e2e", "production"],
    [undefined, "e2e"],
  ])("blocks railway=%s authio=%s without leaking values", (railway, authio) => {
    const errors = quiet();
    let message = "";
    try {
      assertEnvironmentIsolation(bad, "config", {
        RAILWAY_ENVIRONMENT_NAME: railway,
        AUTHIO_ENV: authio,
        AUTHIO_ENV_GUARD_DENYLIST: EXAMPLE_DIGEST,
      });
    } catch (err) {
      message = (err as Error).message;
    }
    expect(message).toContain("AUTHIO_BRANDING_BUCKET");
    expect(message).toContain("AWS_ACCESS_KEY_ID");
    const logged = errors.mock.calls.map((c) => String(c[0])).join("\n") + message;
    expect(logged).not.toContain(EXAMPLE_KEY_ID);
    expect(logged).not.toContain("authio-production-branding");
  });

  it("honours warn-only names but not wildcards", () => {
    quiet();
    const env = {
      RAILWAY_ENVIRONMENT_NAME: "e2e",
      AUTHIO_ENV_GUARD_WARN_ONLY: " AUTHIO_BRANDING_BUCKET ,",
    };
    expect(() =>
      assertEnvironmentIsolation(
        { AUTHIO_BRANDING_BUCKET: "authio-production-branding" },
        "config",
        env,
      ),
    ).not.toThrow();
    const both = {
      AUTHIO_BRANDING_BUCKET: "authio-production-branding",
      BACKUP_S3_BUCKET: "authio-production-db-backups",
    };
    expect(() => assertEnvironmentIsolation(both, "config", env)).toThrow(
      /BACKUP_S3_BUCKET/,
    );
    expect(() =>
      assertEnvironmentIsolation(both, "config", {
        ...env,
        AUTHIO_ENV_GUARD_WARN_ONLY: "*",
      }),
    ).toThrow();
  });
});
