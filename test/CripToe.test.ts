import { describe, test, expect } from "vitest";
import CripToe, {
  type EncryptReturns,
  type EncryptReturnsSafeURL,
  type ExportedWraps,
  type ExportedWrapsBase64,
  type ExportedWrapsSafeURL,
  type WrapKeyReturns,
} from "../src/index";
import { isBase64 } from "thetyster-utils";

/**
 * FIXME: Tests need to be organized better. This setup function is breaking a lot of things.
 **/

async function setup(
  safeURL: boolean | undefined,
  toBase64: boolean | undefined,
) {
  const longTestMessage = `A really long test message that may be encrypted to test whether a really long message can remain under 2000 characters in length for a URL. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.  This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryp`;
  const C = new CripToe(longTestMessage);
  let secret: EncryptReturns;
  let wrappingKeyReturn: WrapKeyReturns["wrappingKey"];
  let wrappedKeyReturn: WrapKeyReturns["wrappedKey"];

  // Typings for secret.
  if (safeURL) {
    secret = (await C.encrypt({
      safeURL,
    })) as EncryptReturnsSafeURL;
  } else if (toBase64) {
    secret = (await C.encrypt({
      toBase64,
    })) as EncryptReturns;
  } else {
    secret = (await C.encrypt()) as EncryptReturns;
  }

  // Typings for wrappingKey and wrapped
  if (safeURL && toBase64) {
    let { wrappingKey, wrappedKey } = (await C.wrapKey({
      export: true,
      safeURL,
      toBase64,
    })) as ExportedWrapsBase64;
    wrappingKeyReturn = wrappingKey;
    wrappedKeyReturn = wrappedKey;
  } else if (safeURL) {
    let { wrappingKey, wrappedKey } = (await C.wrapKey({
      export: true,
      safeURL,
    })) as ExportedWrapsSafeURL;
    wrappingKeyReturn = wrappingKey;
    wrappedKeyReturn = wrappedKey;
  } else if (toBase64) {
    let { wrappingKey, wrappedKey } = (await C.wrapKey({
      export: true,
      toBase64,
    })) as ExportedWrapsBase64;
    wrappingKeyReturn = wrappingKey;
    wrappedKeyReturn = wrappedKey;
  } else {
    let { wrappingKey, wrappedKey } = (await C.wrapKey({
      export: true,
    })) as ExportedWraps;
    wrappingKeyReturn = wrappingKey;
    wrappedKeyReturn = wrappedKey;
  }

  const wrappingKey = wrappingKeyReturn;
  const wrappedKey = wrappedKeyReturn;
  return { C, secret, longTestMessage, wrappingKey, wrappedKey };
}

//prettier-ignore
// {
const variation = [
  /**safeURL    toBase64*/
    [true,      true],
    [false,     false],
    [true,      false],
    [false,     true],
    [undefined, undefined],
    [undefined, true],
    [undefined, false],
    [true,      undefined],
    [false,     undefined],
  ]
// }
describe.each(variation)(
  "CripToe test: #%# safeURL: %s, toBase64: %s",
  async (safeURL, toBase64) => {
    const { C, secret, longTestMessage, wrappingKey, wrappedKey } = await setup(
      safeURL,
      toBase64,
    );
    if (!isBase64(wrappingKey)) {
    }
    class CripToeTest extends CripToe {
      constructor() {
        super("Inner Class Tests");
        this.encrypted; // Must be called inside this mock class to avoid an error in the test.
      }
    }

    describe("Properties", () => {
      test("CripToe should have an encrypted property", () => {
        expect(C).toHaveProperty("encrypted");
        expect(typeof C.encrypted).toMatch(/string|ArrayBuffer/);
        expect(isBase64(C.encrypted)).toBeTruthy();
      });

      test.todo("CripToe should have an initVector property", () => {
        expect(C).toHaveProperty("initVector");
        expect(C.initVector).toBeTypeOf("string");
/*        expect(isBase64(C.initVector)).toBeTruthy();*/
      });

      test("CripToe should not have a key property initially.", () => {
        expect(C).not.toHaveProperty("key");
      });

      test("CripToe should have a cipher property initially.", () => {
        expect(C).not.toHaveProperty("cipher");
      });

      test("'random' should always be different.", () => {
        expect(C.random).not.toBe(C.random);
        expect(C.random).not.toMatchObject(C.random);
        expect(C.random).not.toEqual(C.random);
        expect(C.random).not.toStrictEqual(C.random);
        expect(CripToe.random()).not.toBe(CripToe.random());
        expect(CripToe.random()).not.toMatchObject(CripToe.random());
        expect(CripToe.random()).not.toEqual(CripToe.random());
        expect(CripToe.random()).not.toStrictEqual(CripToe.random());
      });
    });

    describe.shuffle("Methods", () => {
      test("Sha256 should return a hashed string", async () => {
        expect(await C.sha256()).toMatchSnapshot();
      });

      test("encrypt() should encrypt a string", async () => {
        expect(() => new CripToeTest()).toThrowError(
          "Not encrypted yet. You must call the 'encrypt' method before calling this property.",
        );
        expect(secret.key).toBeInstanceOf(CryptoKey);
        expect
          .soft(
            !!(secret.initVector instanceof Uint8Array) ||
              !!isBase64(secret.initVector) ||
              !!isBase64(CripToe.decodeUrlSafeBase64(secret.initVector)),
            `${secret.initVector} was falsey. So, not a Uint8Array nor did it pass the base64 test.`,
          )
          .toBeTruthy();
        if (toBase64 || safeURL) {
          expect(typeof secret.cipher === "string").toBeTruthy();
          if (typeof secret.cipher === "string") {
            expect(
              isBase64(CripToe.decodeUrlSafeBase64(secret.cipher)),
            ).toBeTruthy();
          }
        }
      });

      test.runIf(safeURL || toBase64)(
        "Should create a wrapping key.",
        async () => {
          if (typeof wrappedKey === "string") {
            expect(wrappedKey, "Should be a string.").toBeTypeOf("string");
            if (safeURL) {
              expect(
                isBase64(wrappedKey),
                "Wrapped Key should not be a base64 string",
              ).toBeFalsy();
            } else {
              expect(isBase64(wrappedKey)).toBeTruthy();
            }
            expect(
              safeURL
                ? isBase64(CripToe.decodeUrlSafeBase64(wrappedKey))
                : isBase64(wrappedKey),
              "SafeURL decoded wrapped Key should be a base64 string",
            ).toBeTruthy();
            expect(wrappingKey, "Wrapping Key is not a string.").toBeTypeOf(
              "string",
            );
          }
        },
      );

      test.todo("Should unwrap a key.", async () => {
        const C2 = new CripToe("Wrapping Test");
        if (typeof wrappedKey === "string") {
          const wrappedKeyB64 = CripToe.decodeUrlSafeBase64(wrappedKey);
          const wrappedKeyArrBuff = CripToe.base64ToArrayBuffer(wrappedKeyB64);
          const wrappingKeyJWK = Buffer.from(wrappingKey, "base64url").toString(
            "utf-8",
          );
          await C2.unwrapKey(wrappedKeyArrBuff, wrappingKeyJWK);
          //@ts-ignore Accessing a private property for testing.
          expect(C2._cripKey).toStrictEqual(secret.key);
          expect(
            //@ts-ignore Accessing a private property for testing.
            await C2.decrypt(secret.cipher, C2._cripKey, C.initVector),
          ).toBe(longTestMessage);
        }
      });

      test.todo("Should decrypt an encrypted string", async () => {
        const decrypted = await C.decrypt(
          secret.cipher,
          secret.key,
          secret.initVector,
        );
        expect(decrypted).toBeTruthy();
        expect(decrypted).toBe(longTestMessage);
      });
    });
  },
);

let iterations = 101;
while (iterations--) {
  describe(`URL Encoding test: ${iterations}`, async () => {
    const { C, secret, wrappedKey } = (await setup(true, false)) as {
      C: CripToe;
      secret: EncryptReturnsSafeURL;
      wrappedKey: string;
    };
    test("Should be safely encoded as a base64 URL string", () => {
      expect(secret.cipher).not.toContain("=");
      expect(secret.cipher).not.toContain("+");
      expect(secret.cipher).not.toContain("/");
      expect(secret.initVector).not.toContain("=");
      expect(secret.initVector).not.toContain("+");
      expect(secret.initVector).not.toContain("/");
      expect(wrappedKey).not.toContain("=");
      expect(wrappedKey).not.toContain("+");
      expect(wrappedKey).not.toContain("/");
    });
    test("CripToe.encrypted getter should return a base64 string.", () => {
      expect(C.encrypted).toBeTypeOf("string");
      expect(isBase64(C.encrypted)).toBeTruthy();
    });

    test("Should return URL safe base64", () => {
      const testUrl = new URL(`https://example.com/${secret.cipher}`);
      testUrl.searchParams.set("k", wrappedKey);
      testUrl.searchParams.set("iv", secret.initVector);
      expect(testUrl).toBeDefined();
      expect(testUrl.toString(), "Cipher is not in the URL.").toContain(
        secret.cipher,
      );
      expect(
        testUrl.searchParams.get("k"),
        "Wrapped Key is not in the URL.",
      ).toContain(wrappedKey);
      expect(
        testUrl.searchParams.get("iv"),
        "Init Vector is not in the URL.",
      ).toContain(secret.initVector);
      expect
        .soft(testUrl.toString().length, "Resultant URL is too long.")
        .toBeLessThanOrEqual(2000);
    });

    test("Should decode safe URL back to base64", () => {
      expect(
        CripToe.decodeUrlSafeBase64(C.encrypted),
        "Not a base64 string.",
      ).toMatch(CripToe.decodeUrlSafeBase64(secret.cipher));
    });
  });
}
