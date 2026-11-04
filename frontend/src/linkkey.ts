import {
  IV_BYTES,
  KEY_BYTES,
  SALT_BYTES,
  TAG_BYTES,
  base64urlDecode,
  base64urlEncode,
  unwrapDataKey,
  wrapDataKey,
  type WrappedKey,
} from "./crypto.ts";

/**
 * Fragment formats:
 *   v1: <key>                                  (43 chars, no passphrase)
 *   v2: v2.<salt>.<iv>.<wrappedKey>.<tag>      (passphrase-wrapped key)
 *
 * The server never sees any of this: fragments are not sent in HTTP requests.
 */
export type FragmentMaterial =
  | { version: 1; key: Uint8Array }
  | { version: 2; wrapped: WrappedKey };

export function readFragment(fragment: string): FragmentMaterial | null {
  if (fragment.startsWith("v2.")) {
    const parts = fragment.split(".");
    if (parts.length !== 5) {
      return null;
    }
    const [, saltPart, ivPart, keyPart, tagPart] = parts;
    if (
      !saltPart ||
      !ivPart ||
      !keyPart ||
      !tagPart ||
      !decodesTo(saltPart, SALT_BYTES) ||
      !decodesTo(ivPart, IV_BYTES) ||
      !decodesTo(keyPart, KEY_BYTES) ||
      !decodesTo(tagPart, TAG_BYTES)
    ) {
      return null;
    }
    return {
      version: 2,
      wrapped: {
        salt: saltPart,
        iv: ivPart,
        ciphertext: keyPart,
        tag: tagPart,
      },
    };
  }

  const key = base64urlDecode(fragment);
  if (!key || key.byteLength !== KEY_BYTES) {
    if (key) {
      key.fill(0);
    }
    return null;
  }
  return { version: 1, key };
}

export async function encodeFragment(
  keyBytes: Uint8Array,
  passphrase: string,
): Promise<string> {
  if (passphrase.length === 0) {
    return base64urlEncode(keyBytes);
  }
  const wrapped = await wrapDataKey(keyBytes, passphrase);
  return [
    "v2",
    wrapped.salt,
    wrapped.iv,
    wrapped.ciphertext,
    wrapped.tag,
  ].join(".");
}

export function unlockFragment(
  material: FragmentMaterial,
  passphrase: string,
): Promise<Uint8Array> {
  if (material.version === 1) {
    return Promise.resolve(material.key);
  }
  return unwrapDataKey(material.wrapped, passphrase);
}

function decodesTo(value: string, length: number): boolean {
  const decoded = base64urlDecode(value);
  if (!decoded) {
    return false;
  }
  const ok = decoded.byteLength === length;
  decoded.fill(0);
  return ok;
}
