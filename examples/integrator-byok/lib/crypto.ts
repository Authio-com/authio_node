/**
 * AES-256-GCM helpers for sealing tenant Authio API keys at rest.
 *
 * Reference-only — production integrators should use envelope encryption
 * with a KMS-backed master key. See authio_docs guide:
 * /guides/connect-external-app
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

export interface SealedBlob {
  ciphertext: string;
  iv: string;
  tag: string;
}

function deriveKey(master: string): Buffer {
  const trimmed = master.trim();
  if (trimmed.length >= 32) {
    try {
      const decoded = Buffer.from(trimmed, "base64");
      if (decoded.length >= 32) return decoded.subarray(0, 32);
    } catch {
      /* fall through */
    }
    return Buffer.from(trimmed, "utf8").subarray(0, 32);
  }
  return createHash("sha256").update(trimmed).digest();
}

export function encryptApiKey(plaintext: string, masterKey: string): SealedBlob {
  if (!masterKey) {
    throw new Error("INTEGRATOR_CREDS_KEY is required to seal API keys");
  }
  const key = deriveKey(masterKey);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv);
  const ct = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: ct.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function decryptApiKey(sealed: SealedBlob, masterKey: string): string {
  if (!masterKey) {
    throw new Error("INTEGRATOR_CREDS_KEY is required to open API keys");
  }
  const key = deriveKey(masterKey);
  const iv = Buffer.from(sealed.iv, "base64");
  const tag = Buffer.from(sealed.tag, "base64");
  const ct = Buffer.from(sealed.ciphertext, "base64");
  if (iv.length !== IV_LEN || tag.length !== TAG_LEN) {
    throw new Error("invalid sealed blob");
  }
  const decipher = createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plain.toString("utf8");
}
