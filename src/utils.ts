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

