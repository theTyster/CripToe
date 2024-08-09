import { describe, test, expect } from "vitest";
import CripToe from "../src/index";
import { isBase64, isBase64URL } from "../src/utils";

describe("ReadMe Examples", async () => {
  const url = new URL("https://media.cherrylanefarmdoodles.com/");
  url.searchParams.set("src", "https://example.com/a-secret-image.jpg");
  url.searchParams.set("width", "200");
  url.searchParams.set("height", "200");
  url.searchParams.set("fit", "crop");
  url.searchParams.set("dpr", "2");
  url.searchParams.set("quality", "80");
  const messageToEncrypt = url.searchParams.toString();

  const criptoeKey = new CripToe("I just need a wrappingKey");
  await criptoeKey.encrypt();
  const secret = await criptoeKey.wrapKey({ export: true });
  const criptoe = new CripToe(messageToEncrypt);

  const wrappingKeyStringifiedForYou = JSON.parse(secret.wrappingKey);
  console.log(
"\n***************************************************************\n",
"Here's a free wrapping key for you to use in your application:",
"\n***************************************************************\n",
wrappingKeyStringifiedForYou,
  );
  test("Should obtain a wrapping Key", async () => {
    expect(secret).toBeDefined();
    expect(secret.wrappingKey).toBeDefined();
    expect(secret.wrappedKey).toBeDefined();
    expect(secret.wrappedKey).toBeInstanceOf(ArrayBuffer);
    expect(wrappingKeyStringifiedForYou).toHaveProperty("k");
  });

  // Wrap the key with the secret wrapping key.
  // Extract the wrapped key and reextract the wrapping key formatted for URL.
  const { wrappedKey, wrappingKey } = await criptoe.wrapKey(
    { export: true, safeURL: true, toBase64: false },
    secret.wrappingKey,
  );

  test("Should reobtain Keys", async () => {
    expect(wrappedKey).toBeDefined();
    expect(wrappedKey).toBeTypeOf("string");
    expect(isBase64URL(wrappedKey)).toBe(true);
    expect(isBase64URL(wrappingKey)).toBe(true);
  });

  // Encrypt the data. Get back the cipher and the initialization vector.
  // You can also extract the unwrapped key here. This is the only time the raw key can be extracted out of CripToe.
  const encrypted = (await criptoe.encrypt({
    safeURL: true,
  })) as { cipher: string; initVector: string };

  test("Should encrypt data", async () => {
    expect(encrypted.cipher).toBeDefined();
    expect(encrypted.initVector).toBeDefined();
    expect(isBase64URL(encrypted.cipher)).toBe(true);
    expect(isBase64URL(encrypted.initVector)).toBe(true);

    expect(Buffer.from(encrypted.cipher, "base64url").toString()).not.toBe(criptoe.message);

  });

  url.searchParams.delete("src");
  url.searchParams.delete("width");
  url.searchParams.delete("height");
  url.searchParams.delete("fit");
  url.searchParams.delete("dpr");
  url.searchParams.delete("quality");

  url.pathname = encrypted.cipher;
  url.searchParams.set("iv", encrypted.initVector);
  url.searchParams.set("k", wrappedKey);

  const encryptedURL = url.toString();

  const urlObj = new URL(encryptedURL);

  const encryptedString = urlObj.pathname.split("/")[1];
  const iv = urlObj.searchParams.get("iv") as string;
  const wk = urlObj.searchParams.get("k") as string;

  // Transform the wrapped key into a buffer for unwrapping
  const wrappedBuf = Buffer.from(wk, "base64url");

  // Inject encrypted data into criptoe instance at instantiation
  const criptoeDecrypt = new CripToe(encryptedString);

  // Unwrap the key
  await criptoeDecrypt.unwrapKey(wrappedBuf, secret.wrappingKey);

  // Get the unwrapped key back out
  const { key } = await criptoeDecrypt.encrypt();

  test("Keys should match", async() => {
    expect(key).toBeDefined();
    expect(key).toBeInstanceOf(CryptoKey);
    expect(key).toStrictEqual(encrypted.key);
  })

  // Decrypt 🥳
  const unencryptedMessage = await criptoeDecrypt.decrypt(
    encryptedString,
    key,
    iv,
  );

  const data = new URLSearchParams(unencryptedMessage);

  test("Should decrypt data", async () => {
    expect(data.get("src")).toBe("https://example.com/a-secret-image.jpg");
    expect(data.get("width")).toBe("200");
    expect(data.get("height")).toBe("200");
    expect(data.get("fit")).toBe("crop");
    expect(data.get("dpr")).toBe("2");
    expect(data.get("quality")).toBe("80");
    expect(unencryptedMessage).toBe(messageToEncrypt);
  });

  url.searchParams.get("src");
  url.searchParams.get("width");
  url.searchParams.get("height");
  url.searchParams.get("fit");
  url.searchParams.get("dpr");
  url.searchParams.get("quality");
});
