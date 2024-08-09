import {
  ExportedWraps,
  ExportedWrapsBase64,
  CripToeOptions,
  EncryptReturns,
  Truthy,
  Falsy,
  Wraps,
} from "./index";

import { isBase64, isBase64URL } from "../test/CripToe.test";

/** Provides Sha256 hashing and AES-GCM encryption and decryption of strings. For Node.*/
export default class CripToe {
  /**
   * The message originally provided to the instance encoded into a Uint8Array.
   **/
  encoded: Uint8Array;

  /**
   * @param message - String to be encrypted or hashed.
   **/
  constructor(
    message: string,
    opts?: { silenceWarnings?: boolean },
    /*password?: string,*/
  ) {
    if (message.length > 1260 && !opts?.silenceWarnings) {
      console.warn(
        `WARNING: The message supplied to ${this.constructor.name} is possibly too long for a URL.\nTests show that messages longer than 1,260 characters may exceed the maximum recommended length for a URL, which is 2,084 characters.\nlength:\n${message.length}\nmessage:\n${message}`,
      );
    }
    this.#silenced = opts?.silenceWarnings || false;
    this.#message = message;
    this.encoded = new TextEncoder().encode(this.#message);

    // ENSURES THAT THE CIPHER IS ONLY GENERATED ONCE.
    this.#cipher = undefined;

    // GENERATES THE ENCRYPTION KEY ONLY ONCE AND ONLY WHEN NEEDED.
    // This method uses a generator function to allow for the key to only be
    // generated when needed and only once. Additionally, this method is
    // scalable to allow for password based keys. If that is needed one day.
    this.#cripKeyWalk = this.genCripKey(/*password ? password : undefined*/);
    this.#cripKeyWalk.next().then((key) => {
      this.#cripKey = key.value as undefined;
    });

    // ENSURES THAT THE WRAP KEY IS ONLY GENERATED ONCE.
    // Requires that salt be provided. Salt is not provided here. Although, you
    // can use 'Cripto.random()' to generate salt.
    this.#wrappedKey = undefined;
  }

  /**
   * Hashes any string into a Sha256 hash. By default will hash the mesage initially provided to the constructor.
   **/
  async sha256(message?: string) {
    if (!message && typeof this.message === "string") message = this.message;
    const encoded = message ? new TextEncoder().encode(message) : this.encoded;
    return this.CRYP.digest("SHA-256", encoded).then((hash) => {
      const hashArray = Array.from(new Uint8Array(hash));
      const hashHex = hashArray
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
      return hashHex;
    });
  }

  /**
   * Encrypts the message into AES-GCM.
   * AES-GCM as opposed to AES-CBC or AES-CTR includes checks that the ciphertext has not been modified.
   **/
  async encrypt(options?: CripToeOptions) {
    if (!this.#cripKey) {
      this.#cripKey = await this.#cripKeyWalk.next().then((key) => key.value);
    }
    if (!this.#cipher) {
      const iv = this.#iv;
      const key = this.#cripKey!;
      const promisedCipher = await this.CRYP.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        key,
        this.encoded,
      );
      this.#cipher = promisedCipher;
    }
    if (options?.safeURL) {
      return {
        cipher: Buffer.from(this.#cipher).toString("base64url"),
        initVector: Buffer.from(this.#iv).toString("base64url"),
        key: this.#cripKey,
      } as const satisfies EncryptReturns;
    } else if (options?.toBase64) {
      return {
        cipher: Buffer.from(this.#cipher).toString("base64"),
        initVector: Buffer.from(this.#iv).toString("base64"),
        key: this.#cripKey,
      } as const satisfies EncryptReturns;
    } else {
      return {
        cipher: this.#cipher,
        initVector: this.#iv,
        key: this.#cripKey,
      } as const satisfies EncryptReturns;
    }
  }

  /**
   * Decrypts any AES-GCM encrypted data provided you have the necessary parameters.
   *
   * @param key - The Key used to initially encrypt. {@see CripToe.cripKey}
   * @param iv - The Initialization Vector or, nonce, used to salt the encryption. Provided as base64 string.
   * @param cipher - The encrypted data to be decrypted. Provided as base64 string.
   **/
  async decrypt(
    cipher: EncryptReturns["cipher"],
    key: EncryptReturns["key"],
    initVector: EncryptReturns["initVector"],
  ) {
    if (typeof cipher === "string") {
      if (isBase64(cipher)) {
        cipher = Buffer.from(cipher, "base64");
      } else if (isBase64URL(cipher)) {
        cipher = Buffer.from(cipher, "base64url");
      } else if (cipher === this.#message) {
        cipher = this.messageBuf;
      }
    }

    if (cipher instanceof Buffer) {
      cipher = CripToe.arrayBufferFrom(cipher) as ArrayBuffer;
    }

    if (typeof initVector === "string") {
      initVector = Buffer.from(initVector, "base64url");
    }

    if (!(key instanceof CryptoKey))
      throw new Error(
        "You must provide a valid encryption key to decrypt. It should be an instance of CryptoKey.",
      );

    if (!(cipher instanceof ArrayBuffer))
      throw new Error(
        "You must provide a valid encrypted message to decrypt. It should be an instance of ArrayBuffer or a string.",
      );

    const decrypted = await this.CRYP.decrypt(
      {
        name: "AES-GCM",
        iv: initVector,
      },
      key,
      cipher,
    );
    this.#message = decrypted;
    return new TextDecoder("utf-8").decode(decrypted);
  }

  /**
   * Takes any given, (wrapped) key and unencrypts it with a provided wrapping key. The wrapping key is expected to be in JWK format. The unwrapped key then becomes the key used to encrypt and decrypt messages. NOTE: The unwrapped key and the wrapped key are stored in the instance and never returned out of it. Except for the first time a message is encrypted.
   * @param wrappedKey - The key to be unwrapped. Provided as a base64 string.
   * @param wrappingKeyString - The key used to wrap the secret key. Provided as a JSON Web Key (JWK) string.
   **/
  async unwrapKey(wrappedKey: ArrayBuffer, wrappingKeyString: string) {
    const wrappingKey = await this.#parseJWk(wrappingKeyString);
    const unWrappedKey = await this.CRYP.unwrapKey(
      "jwk",
      wrappedKey,
      wrappingKey,
      {
        name: "AES-KW",
      },
      {
        name: "AES-GCM",
        length: 256,
      },
      true,
      ["encrypt", "decrypt"],
    );

    this.#wrappedKey = wrappedKey;
    this.#cripKey = unWrappedKey;
    return true;
  }

  /**
   * Wraps the key in JWK (Json Web Key) format using AES-KW. The benefit of AES-KW is that it doesn't require an Initialization Vector. See: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey
   * Even if this function is called multiple times the wrapped key will only be generated once.
   * Subsequent calls will simply return the originally wrapped key.
   *
   * @param wrappingKey (JWK) - The key used to wrap the secret key. If not provided, a new key will be generated.
   * @param opts - Options for exporting the wrapped key:
   * - export: boolean - Whether to export the wrapped key. Will return the wrapped key and the wrapping key in an Object:
   *   {
   *   wrappingKey: string,
   *   wrappedKey: ArrayBuffer
   *   }
   *  - safeURL: boolean - Whether to return the properties in the returned object as a special base64 encoding with special characters removed. To convert them back to standard base64 {@see CripToe.decodeUrlSafeBase64.}
   *  - toBase64: boolean - Whether to return the properties in the returned object as a standard base64 encoding. to convert them back to an ArrayBuffer @see CripToe.base64ToArrayBuffer.
   **/

  async wrapKey<E, S, B>(
    opts?: {
      export: Truthy<E> | Falsy;
      safeURL?: Truthy<S> | Falsy;
      toBase64?: Truthy<B> | Falsy;
    },
    wrappingKeyJWK?: string,
  ): Promise<Wraps<E, S, B>> {
    // Check for encryption key.
    if (!this.#cripKey) {
      this.#cripKey = await this.#cripKeyWalk.next().then((key) => key.value);
    }
    if (this.#wrappedKey) {
      throw new Error("The key has already been wrapped.");
    }

    // Generate a key to wrap the key.
    // Intentionally not using the same method for generating a key as the one used to encrypt.
    let wrappingKey: CryptoKey;
    if (wrappingKeyJWK) {
      wrappingKey = await this.#parseJWk(wrappingKeyJWK);
    } else {
      wrappingKey = await this.CRYP.generateKey(
        {
          name: "AES-KW",
          length: 256,
        },
        true,
        ["wrapKey", "unwrapKey"],
      );
    }

    const wrappedKey = await this.CRYP.wrapKey(
      "jwk",
      this.#cripKey!,
      wrappingKey,
      {
        name: "AES-KW",
      },
    );

    this.#wrappedKey = wrappedKey;

    const wrappingKeyJwk = await this.CRYP.exportKey("jwk", wrappingKey);
    const wrappingKeyString = JSON.stringify(wrappingKeyJwk);
    const exported: ExportedWraps = {
      wrappingKey: wrappingKeyString,
      wrappedKey: this.#wrappedKey,
    };
    if (opts?.export) {
      if (opts?.safeURL) {
        const safeURLExport: Wraps<true, true, false> = {
          wrappingKey: Buffer.from(wrappingKeyString).toString("base64url"),
          wrappedKey: Buffer.from(wrappedKey).toString("base64url"),
        };
        return safeURLExport as unknown as Wraps<E, S, B>;
      } else if (opts?.toBase64) {
        const base64Export: ExportedWrapsBase64 = {
          wrappingKey: Buffer.from(wrappingKeyString).toString("base64"),
          wrappedKey: Buffer.from(wrappedKey).toString("base64"),
        };
        return base64Export as unknown as Wraps<E, S, B>;
      } else {
        return exported as unknown as Wraps<E, S, B>;
      }
    } else return exported as unknown as Wraps<E, S, B>;
  }

  /**
   * The message encrypted into base64.
   **/
  get encrypted() {
    if (this.#cipher instanceof ArrayBuffer)
      return Buffer.from(this.#cipher).toString("base64");
    else
      throw new Error(
        "Not encrypted yet. You must call the 'encrypt' method before calling this property.",
      );
  }

  /**
   * The Initial Vector, or nonce, used to salt the encryption.
   **/
  get initVector(): EncryptReturns["initVector"] {
    return this.#iv;
  }

  /**
   * Converts the message from base64 to an array buffer.
   **/
  get messageBuf() {
    if (
      !(this.#message instanceof ArrayBuffer) &&
      !(this.#message instanceof SharedArrayBuffer) &&
      isBase64(this.#message)
    ) {
      const messageBuf = Buffer.from(this.#message, "base64");
      return CripToe.arrayBufferFrom(messageBuf);
    } else if (
      !(this.#message instanceof ArrayBuffer) &&
      !(this.#message instanceof SharedArrayBuffer) &&
      isBase64URL(this.#message)
    ) {
      const messageBuf = Buffer.from(this.#message, "base64url");
      return CripToe.arrayBufferFrom(messageBuf);
    } else if (
      !(this.#message instanceof ArrayBuffer) &&
      !(this.#message instanceof SharedArrayBuffer)
    ) {
      return this.encoded.buffer;
    } else return this.#message;
  }

  /**
   * The message originally provided to the instance for encryption.
   **/
  get message() {
    if (this.#message instanceof ArrayBuffer) {
      return new TextDecoder().decode(this.#message);
    } else return this.#message;
  }

  static arrayBufferFrom(messageBuf: Buffer): ArrayBuffer {
    const arrBuf = new ArrayBuffer(messageBuf.length);
    const messageView = new Uint8Array(arrBuf);
    for (let i = 0; i < messageBuf.length; i++) {
      messageView[i] = messageBuf[i];
    }
    const arrayBuf = new Uint8Array(messageView).buffer;
    return arrayBuf;
  }

  #isNode = typeof process === "object" && process + "" === "[object process]";
  #cipher: Exclude<EncryptReturns["cipher"], string>;
  #cripKey: EncryptReturns["key"];
  #cripKeyWalk: AsyncGenerator<undefined, CryptoKey, unknown>;
  #wrappedKey: ArrayBuffer | undefined;

  /**
   * The message originally provided to the instance for encryption.
   **/
  #message: string | ArrayBufferLike;

  /**
   * Used to silence warnings.
   **/
  #silenced: boolean;

  private CRYP = (() => {
    if (this.#isNode) {
      const cryp = crypto.subtle;
      if (cryp instanceof SubtleCrypto) return cryp;
      else throw new Error("SubtleCrypto is not available.");
    } else throw new Error("You are not in a supported environment.");
  })();

  async #parseJWk(JWK: string) {
    const wrappingKeyJwk = JSON.parse(JWK);
    return await this.CRYP.importKey(
      "jwk",
      wrappingKeyJwk,
      {
        name: "AES-KW",
      },
      true,
      ["wrapKey", "unwrapKey"],
    );
  }

  get random() {
    if (this.#isNode) {
      return crypto.getRandomValues(new Uint8Array(intArrLength));
    } else throw new Error("You are not in a supported environment.");
  }

  static random = () => {
    if (typeof process === "object" && process + "" === "[object process]") {
      return crypto.getRandomValues(new Uint8Array(intArrLength));
    } else throw new Error("You are not in a supported environment.");
  };

  /**
   * Intentional dupe of 'get random()'. To avoid accidentally reusing an initVector
   **/
  #iv = (() => {
    if (this.#isNode) {
      return crypto.getRandomValues(new Uint8Array(intArrLength));
    } else throw new Error("You are not in a supported environment.");
  })();

  /**The key used to encrypt and decrypt the message.**/
  private async *genCripKey(password?: string) {
    yield undefined;
    if (!password) {
      return await this.CRYP.generateKey(
        {
          name: "AES-GCM",
          length: 256,
        },
        true,
        ["encrypt", "decrypt"],
      );
    } else {
      return await this.CRYP.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey", "deriveBits"],
      );
    }
  }
}

/**
 * Used to determine the length of Uint8Array's for random values.
 **/
const intArrLength = 12;
