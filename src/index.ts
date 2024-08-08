import { ENCRYPT_RETURNS, WRAPKEY_RETURNS } from "./constants";

export { default } from "./CripToe";

export type Falsy = false | "" | 0 | null | undefined;

export const isTruthy = <T>(x: T | Falsy): x is T => !!x;

export type DefinitelyTruthy<T> = false extends T
  ? never
  : 0 extends T
    ? true
    : "" extends T
      ? true
      : null extends T
        ? true
        : undefined extends T
          ? true
          : unknown extends T
            ? true
            : T;

export type Wraps<E, S, B> =
    E extends DefinitelyTruthy<E>
      ? S extends DefinitelyTruthy<S>
        ? B extends DefinitelyTruthy<B>
          ? ExportedWrapsBase64
          : ExportedWrapsSafeURL
        : ExportedWraps
      : never;

export type EncryptReturns = typeof ENCRYPT_RETURNS;
export type WrapKeyReturns = typeof WRAPKEY_RETURNS;

export interface CripToeOptions {
  /**
   * Elicits whether the function should out put a URL safe base64 string or a regular base64 string.
   * {@see encodeUrlSafeBase64}
   * {@see decodeSafeURL}
   ***/
  safeURL?: boolean;
  toBase64?: boolean;
}
export type EncryptReturnsSafeURL = {
  /**
   * Data encrypted to Base64 with special URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly cipher: string;
  /**
   * This is the only time the key is returned anywhere.
   * It is always returned as an instance of CryptoKey.
   * If you don't want it to be available in scope, don't destructure it.
   **/
  readonly key: CryptoKey;
  /**
   * Init Vector converted to Base64 with special URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   * Init Vector does not need to be a secret.
   **/
  readonly initVector: string;
};

export type EncryptReturnsBase64 = {
  /**
   * Data encrypted and encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer}
   **/
  readonly cipher: string;
  /**
   * This is the only time the key is returned anywhere.
   * It is always returned as an instance of CryptoKey.
   * If you don't want it to be available in scope, don't destructure it.
   **/
  readonly key: CryptoKey;
  /**
   * Data encrypted and encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer}
   **/
  readonly initVector: string;
};

export type ExportedWraps = {
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
  readonly wrappingKey: string;
  /**
   * The secret key returned as encrypted by the wrapping key.
   **/
  readonly wrappedKey: ArrayBuffer;
};

export type ExportedWrapsSafeURL = {
  /**
   * Wrapping key converted to Base64 with special URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappingKey: string;
  /**
   * Secret key encrypted by wrapping key and converted to Base64 with special
   * URL characters replaced.
   * Decode it back into Base64 with {@see CripToe.decodeUrlSafeBase64.}
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappedKey: string;
};

export type ExportedWrapsBase64 = {
  /*nv$h{*
   * Wrapping key encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappingKey: string;
  /**
   * Secret Key encrypted and encoded to Base64.
   * Decode it back into an ArrayBuffer with {@see CripToe.base64ToArrayBuffer.}
   **/
  readonly wrappedKey: string;
};
