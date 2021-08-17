import * as crypto from "crypto";
import { HashAlgorithm } from "./types";

const HASH_ENCODING = "hex";

export function bufferToSha1(buffer: Buffer): string {
  const hash = crypto.createHash(HashAlgorithm.Sha1);
  hash.setEncoding(HASH_ENCODING);
  hash.update(buffer);
  hash.end();
  return hash.read().toString(HASH_ENCODING);
}
