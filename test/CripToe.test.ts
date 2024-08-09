import { describe, test, expect } from "vitest";
import CripToe, { type EncryptReturns, type ExportedWraps } from "../src/index";

export function isBase64(str: string): boolean {
  const notBase64 = /[^A-Z0-9+\/=]/i;
  const len = str.length;
  if (!len || len % 4 !== 0 || notBase64.test(str)) {
    return false;
  }
  const firstPaddingChar = str.indexOf("=");
  return (
    firstPaddingChar === -1 ||
    firstPaddingChar === len - 1 ||
    (firstPaddingChar === len - 2 && str[len - 1] === "=")
  );
}

export function isBase64URL(str: string): boolean {
  const notBase64 = /[^A-Z0-9-_]/i;
  const len = str.length;
  const base64 = Buffer.from(str, "base64url").toString("base64");
  if (isBase64(base64)) {
    return true;
  }
  if (!len || len % 4 !== 0 || notBase64.test(str)) {
    return false;
  } else return true;
}

const testWrappingKey = {
  key_ops: ["wrapKey", "unwrapKey"],
  ext: true,
  kty: "oct",
  k: "G9a4N-kkNmJuw0qFHGoQYRCEpavphPddcpwjGnnRKBk",
  alg: "A256KW",
};

const testWrappingKeyStringified = JSON.stringify(testWrappingKey);

describe.each([
  ["here's a random string"],
  ["here's another one."],
  ["here's a third one."],
  ["here's a fourth one."],
  ["here's a fifth one."],
  ["😄😱👀🟥😆🏄🕺"],
  ["┬┴┬┴┤(･_├┬┴┬┴)"],
])("base64 Testers", (string: string) => {
  const base64 = Buffer.from(string).toString("base64");
  const base64url = Buffer.from(base64, "base64").toString("base64url");
  test("isBase64URL should return true for base64url strings", () => {
    expect(
      isBase64URL(base64url),
      `${string} did not pass the base64 test`,
    ).toBeTruthy();
  });
  test("isBase64 should return true for base64 strings", () => {
    expect(
      isBase64(base64),
      `${string} did not pass the base64 test`,
    ).toBeTruthy();
  });
});

async function setup(
  safeURL: boolean | undefined,
  toBase64: boolean | undefined,
) {
  const longTestMessage = `A really long test message that may be encrypted to test whether a really long message can remain under 2000 characters in length for a URL. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.  This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected. This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryption processes are working as expected.This is a test message that will be encrypted and then decrypted to ensure that the encryption and decryp`;
  const C = new CripToe(longTestMessage);
  let secret: EncryptReturns;
  let wrappingKeyReturn: ExportedWraps["wrappingKey"];
  let wrappedKeyReturn: ExportedWraps["wrappedKey"];

  // Typings for secret.
  if (safeURL) {
    secret = await C.encrypt({
      safeURL,
    });
  } else if (toBase64) {
    secret = (await C.encrypt({
      toBase64,
    })) as EncryptReturns;
  } else {
    secret = (await C.encrypt()) as EncryptReturns;
  }

  // Typings for wrappingKey and wrapped
  if (safeURL && toBase64) {
    let { wrappingKey, wrappedKey } = await C.wrapKey(
      {
        export: true,
        safeURL,
        toBase64,
      },
      testWrappingKeyStringified,
    );
    return { C, secret, longTestMessage, wrappingKey, wrappedKey };
  } else if (safeURL) {
    let { wrappingKey, wrappedKey } = await C.wrapKey(
      {
        export: true,
        safeURL,
      },
      testWrappingKeyStringified,
    );
    return { C, secret, longTestMessage, wrappingKey, wrappedKey };
  } else if (toBase64) {
    let { wrappingKey, wrappedKey } = await C.wrapKey(
      {
        export: true,
        toBase64,
      },
      testWrappingKeyStringified,
    );
    return { C, secret, longTestMessage, wrappingKey, wrappedKey };
  } else {
    let { wrappingKey, wrappedKey } = await C.wrapKey(
      {
        export: true,
      },
      testWrappingKeyStringified,
    );
    return { C, secret, longTestMessage, wrappingKey, wrappedKey };
  }
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
describe.shuffle.each(variation)(
  "CripToe test: #%# safeURL: %s, toBase64: %s",
  async (safeURL: boolean, toBase64: boolean) => {
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

    describe.shuffle("Properties", () => {
      test("CripToe should have an encrypted property", () => {
        expect(C).toHaveProperty("encrypted");
        expect(typeof C.encrypted).toMatch(/string|ArrayBuffer/);
        expect(isBase64(C.encrypted)).toBeTruthy();
      });

      test.runIf(toBase64)("CripToe should have an initVector property", () => {
        expect(C).toHaveProperty("initVector");
        if (
          !(C.initVector instanceof Uint8Array) ||
          typeof C.initVector === "string"
        )
          throw new Error("initVector is not a Uint8Array or a string.");
        expect(
          C.initVector.byteLength,
          "Byte length has changed. Check 'intArrLength'",
        ).toBe(12);
        expect(
          C.initVector,
          "initVector is changing whenever it is accessed.",
        ).toStrictEqual(C.initVector);
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
              !!isBase64URL(secret.initVector),
            `${secret.initVector} was falsey. So, not a Uint8Array nor did it pass the base64 test.`,
          )
          .toBeTruthy();
        if (toBase64 || safeURL) {
          expect(typeof secret.cipher === "string").toBeTruthy();
          if (typeof secret.cipher === "string") {
            expect(
              isBase64URL(secret.cipher) || isBase64(secret.cipher),
              `Cipher is not base64: ${secret.cipher}`,
            ).toBeTruthy();
          }
        }
      });

      test.runIf(!safeURL && !toBase64)(
        "Should create a wrapping key.",
        async () => {
          const C2 = new CripToe("test");
          const keys = await C2.wrapKey({ export: true }, wrappingKey);
          expect(keys).toBeDefined();
        },
      );

      test("Should wrap a key.", async () => {
        const C2 = new CripToe("test");
        const wrapped = await C2.wrapKey(
          { export: true, safeURL, toBase64 },
          testWrappingKeyStringified,
        );
        expect(wrapped).toBeDefined();
        expect(wrapped).toBeInstanceOf(Object);
        expect(wrapped).toHaveProperty("wrappedKey");
        expect(wrapped).toHaveProperty("wrappingKey");
        if (safeURL || toBase64)
        //@ts-ignore - This is a test for types.
          expect(wrapped.wrappedKey).toBeTypeOf('strin:g');
        //@ts-ignore - This is a test for types.
        else expect(wrapped.wrappedKey).toBeInstanceOf(ArrayBuffer);
        //@ts-ignore - This is a test for types.
        expect(wrapped.wrappingKey).toBeTypeOf("string");
      });

      test("Should decrypt an encrypted string", async () => {
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
    const { C, secret, wrappedKey } = await setup(true, false);
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
      if (
        wrappedKey instanceof ArrayBuffer ||
        secret.initVector instanceof Uint8Array
      )
        throw new Error(
          "Wrapped Key is not a string or Init Vector is not a Uint8Array.",
        );
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
  });
}
