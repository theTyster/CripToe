import { ENCRYPT_RETURNS, WRAPKEY_RETURNS } from "./constants";

export { default } from "./CripToe";

export type Falsy = false | "" | 0 | null | undefined;

export type False = Falsy;
export type True = Truthy<true>;

export const isTruthy = <T>(x: T | Falsy): x is T => !!x;

export type Truthy<T> = false extends T
  ? never
  : 0 extends T
    ? never
    : "" extends T
      ? never
      : null extends T
        ? never
        : undefined extends T
          ? never
          : unknown extends T
            ? never
            : T;


export type Wraps<E, S, B> = E extends True
  ? S extends B
    ? S extends True
      ? never
      : ExportedWraps
    : S extends True
      ? ExportedWrapsSafeURL
      : B extends False
        ? ExportedWrapsSafeURL
        : S extends False
          ? ExportedWrapsBase64
          : B extends False
            ? ExportedWrapsBase64
            : never
  : E extends False
    ? ExportedWraps
    : never;

export type ENCRYPT_RETURNS = typeof ENCRYPT_RETURNS;
export type WRAPKEY_RETURNS = typeof WRAPKEY_RETURNS;

export interface EncryptReturns {
  /**
   * Data encrypted and encoded to either base64, base64url or ArrayBuffer.
   **/
  readonly cipher: ENCRYPT_RETURNS["cipher"];
  /**
   * This is the only time the encryption key is returned.
   * It is always returned as an instance of CryptoKey.
   * If you don't want it to be available in scope, don't destructure it.
   **/
  readonly key: ENCRYPT_RETURNS["key"];
  /**
   * The Initial Vector, or nonce, used to salt the encryption.
   * Always returned as a Uint8Array.
   **/
  readonly initVector: ENCRYPT_RETURNS["initVector"];
}

export interface CripToeOptions {
  /**
   * Elicits whether the function should out put a URL safe base64 string or a regular base64 string.
   * {@see encodeUrlSafeBase64}
   * {@see decodeSafeURL}
   ***/
  safeURL?: boolean;
  toBase64?: boolean;
}
export interface EncryptReturnsSafeURL extends EncryptReturns {
  /**
   * Data encrypted to Base64 with special URL characters replaced.
   **/
  readonly cipher: Exclude<EncryptReturns["cipher"], ArrayBuffer>;
}

export interface EncryptReturnsBase64 extends EncryptReturns {
  /**
   * Data encrypted and encoded to Base64.
   **/
  readonly cipher: Exclude<EncryptReturns["cipher"], ArrayBuffer>;
}

export interface ExportedWraps {
  /**
   * The key used to wrap the secret key. Returned as a JSON Web Key (JWK)
   * exported and stringified.
   *
   * JWK's are shaped something like this:
   *{
   *  "crv": "P-384",
   *  "d": "wouCtU7Nw4E8_7n5C1-xBjB4xqSb_liZhYMsy8MGgxUny6Q8NCoH9xSiviwLFfK_",
   *  "ext": true,
   *  "key_ops": ["sign"],
   *  "kty": "EC",
   *  "x": "SzrRXmyI8VWFJg1dPUNbFcc9jZvjZEfH7ulKI1UkXAltd7RGWrcfFxqyGPcwu6AQ",
   *  "y": "hHUag3OvDzEr0uUQND4PXHQTXP5IDGdYhJhL-WLKjnGjQAw0rNGy5V29-aV-yseW"
   *};
   **/
  readonly wrappingKey: WRAPKEY_RETURNS["wrappingKey"];
  /**
   * The secret key returned as encrypted by the wrapping key.
   **/
  readonly wrappedKey: WRAPKEY_RETURNS["wrappedKey"];
}

export interface ExportedWrapsSafeURL extends ExportedWraps {
  /**
   * Wrapping key converted to Base64 with special URL characters replaced.
   **/
  readonly wrappingKey: ExportedWraps["wrappingKey"];
  /**
   * Secret key encrypted by wrapping key and converted to Base64 with special
   * URL characters replaced.
   **/
  readonly wrappedKey: Exclude<ExportedWraps["wrappedKey"], ArrayBuffer>;
}

export interface ExportedWrapsBase64 extends ExportedWraps {
  /*nv$h{*
   * Wrapping key encoded to Base64.
   **/
  readonly wrappingKey: ExportedWraps["wrappingKey"];
  /**
   * Secret Key encrypted and encoded to Base64.
   **/
  readonly wrappedKey: Exclude<ExportedWraps["wrappedKey"], ArrayBuffer>;
}
