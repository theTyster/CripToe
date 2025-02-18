import { describe, test, expect } from "vitest";
import CripToe from "../src/index";
import { isBase64, isBase64URL } from "../src/utils";
import { base64 } from "@hexagon/base64";

describe("Sanity Checks", async () => {
  const criptoe = new CripToe("hi");
  const encrypted = (await criptoe.encrypt({
    safeURL: true,
  })) as { cipher: string; initVector: string };

  test("Validate with my own base64 tests", () => {
    // My own version of base64 string validation.
    expect(isBase64URL(encrypted.cipher)).toBe(true);
    expect(isBase64URL(encrypted.initVector)).toBe(true);
  });

  test("Dependencies", () => {
    // Dependency Sanity checks
    expect(base64.toString(encrypted.cipher, Boolean("url"))).not.toBe(
      criptoe.message,
    );
    const b64u = base64.fromString("hello", Boolean("url"));
    expect(b64u).not.toEqual("hello");
    expect(base64.toString(b64u, Boolean("url"))).toEqual("hello");
  });
});
