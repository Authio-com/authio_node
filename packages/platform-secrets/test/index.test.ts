import { afterEach, describe, expect, it, vi } from "vitest";

const sendMock = vi.fn();

vi.mock("@aws-sdk/client-secrets-manager", () => ({
  SecretsManagerClient: class {
    send = sendMock;
  },
  GetSecretValueCommand: class {
    constructor(public input: { SecretId: string }) {}
  },
}));

afterEach(() => {
  vi.clearAllMocks();
  delete process.env.AUTHIO_AWS_SECRET_IDS;
  delete process.env.AWS_REGION;
  delete process.env.PREEXISTING_KEY;
  delete process.env.NEW_KEY;
});

describe("bootstrapPlatformSecrets", () => {
  it("no-ops when AUTHIO_AWS_SECRET_IDS is unset", async () => {
    const { bootstrapPlatformSecrets } = await import("../src/index");
    await bootstrapPlatformSecrets();
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("loads JSON keys into process.env without overwriting existing values", async () => {
    process.env.AUTHIO_AWS_SECRET_IDS = "authio/production/platform";
    process.env.PREEXISTING_KEY = "keep-me";
    sendMock.mockResolvedValueOnce({
      SecretString: JSON.stringify({
        PREEXISTING_KEY: "should-not-replace",
        NEW_KEY: "from-sm",
      }),
    });

    const { bootstrapPlatformSecrets } = await import("../src/index");
    await bootstrapPlatformSecrets();

    expect(sendMock).toHaveBeenCalledTimes(1);
    expect(process.env.PREEXISTING_KEY).toBe("keep-me");
    expect(process.env.NEW_KEY).toBe("from-sm");
  });
});
