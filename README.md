# CripToe
A very simple encryption/decryption library for Node.js. It uses the Web Crypto API to encrypt and decrypt data. It is designed to be used in a Node.js environment.
Be careful anytime you are handling encryption client-side with or without this library. It is very easy to expose your encryption key if you are not careful.

I created this library to help me manage access to a Cloudflare Image Transformations Worker.

I wanted to be able to transform images with a secret transformation url that was provided by the worker. But, I didn't want this to be exposed since Cloudflare Image Transformations can cost money if someone were to abuse it.

Cloudflare provides an example on how to do this here: https://developers.cloudflare.com/images/manage-images/serve-images/serve-private-images

I just wanted something that was a little easier to use.

# Simple Usage Example:

## Gathering Data
Assuming you have some data you want to encrypt and put in a url. Maybe an image you don't want to expose the real url to.
```typescript
const url = new URL("https://media.cherrylanefarmdoodles.com/");
url.searchParams.set("src", "https://example.com/a-secret-image.jpg");
```

I'll add some extra data that I don't want to expose. In this case information about the image transformations I want.
```typescript
url.searchParams.set("width", "200");
url.searchParams.set("height", "200");
url.searchParams.set("fit", "crop");
url.searchParams.set("dpr", "2");
url.searchParams.set("quality", "80");
```

Now we'll just turn this into a string that we can encrypt.
```typescript
const messageToEncrypt = url.searchParams.toString();
```

## Encryption
First, generate a wrapping key that will be used to wrap (encrypt) the secret data key. (That's right, we'll have two keys. 🔑🔑)
The wrapping key will only be used for encrypting and decrypting the data key. It should be kept somewhere secure since having it will allow you to decrypt the data key which would, in turn, allow you to decrypt the data.
```typescript
import CripToe from "criptoe";

const criptoeKey = new CripToe('I just need a wrappingKey');
await criptoeKey.encrypt();
const secret = await criptoeKey.wrapKey({ export: true });
```

Now we can encrypt the data.
Place the string in the CripToe instance at instantiation.
```typescript
const criptoe = new CripToe(messageToEncrypt);

// Wrap the key with the secret wrapping key.
// Extract the wrapped key and reextract the wrapping key formatted for URL.
const { wrappedKey, wrappingKey } = await criptoe
.wrapKey({ export: true, safeURL: true, toBase64: false },
secret.wrappingKey
);

// Encrypt the data. Get back the cipher and the initialization vector.
// You can also extract the unwrapped key here. This is the only time the raw
// key can be extracted out of CripToe.
const { cipher, initVector, /*key*/ } = (await criptoe.encrypt({
safeURL: true,
})) as { cipher: string; initVector: string };
```


Now you can place the cipher, initialization vector, and wrapped key in the worker's URL.
```typescript
url.searchParams.delete("src");
url.searchParams.delete("width");
url.searchParams.delete("height");
url.searchParams.delete("fit");
url.searchParams.delete("dpr");
url.searchParams.delete("quality");

url.pathname = cipher;
url.searchParams.set("iv", initVector);
url.searchParams.set("k", wrappedKey);
```

End result will look something like this:
https://media.cherrylanefarmdoodles.com/X_OXmazu5yT5lH0zKvXatVBafj_4kZjMzzUMG9KlJ6IORR5HIjr3vu0ZY34Az1otEENfYdxihWFgFLX1btm3DxlU97P6ccWJmd_8Z8gBZvyCcdRaVCFllgaiV06bMHbI42LmmcivogpfEPb4FE9IBdIhv8m4NN8LzKenH8FSWU8Hh1KyJB-PJ1JeshBPd_BJP5bf280PdGI?iv=fITNSkC9i-12Q24e&k=jpt-7xt1dSZwYuhwcFLlH8c9bGwZ4g4YVksRP_Rvxj2mV_twIpOv0qs8FPvBltMKmGOclO-bITbqaxA9B5YeYxQCxkEsZo471I_frMaQ7YKKsCkcKcQE6_yLF3Okhnrvl9IvcG5dhslCPgUFoM9nronCD17ZFa9_-Z-FwL3h4ZanZdCLMSBseQ

## Decryption
Now, on another system when you receive the URL in a request, you can decrypt the data.
```typescript
import CripToe from "criptoe";

const urlObj = new URL(request.url);
```

Get data out of url
```typescript
const encryptedString = urlObj.pathname.split("/")[1];
const initVector = urlObj.searchParams.get("iv") as string;
const wrappedKey = urlObj.searchParams.get("k") as string;

// Transform the wrapped key into a buffer for unwrapping
const wrappedBuf = Buffer.from(wrappedKey, "base64url");

// Inject encrypted data into criptoe instance at instantiation
const criptoe = new CripToe(encryptedString);

// Unwrap the key
await criptoe.unwrapKey(wrappedBuf, secretWrappingKey);

// Get the unwrapped key back out
const { key } = await criptoe.encrypt();

// Decrypt 🥳
const unencryptedMessage = await criptoe.decrypt(encryptedString, key, initVector);

const imgURL = new URL(unencryptedMessage);
imgURL.searchParams.get("width");
imgURL.searchParams.get("height");
imgURL.searchParams.get("fit");
imgURL.searchParams.get("dpr");
imgURL.searchParams.get("quality");

// ....
```

# More examples, please!

A working test for the code provided in this readme can be found at [here](test/readme.test.ts).

If you use this library, you don't need to buy me a coffee. ☕
But, if you want to help improve it, PR's are always welcome. 🤝
