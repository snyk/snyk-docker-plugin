import * as crypto from "crypto";
import { HashAlgorithm } from "./types";

const HASH_ENCODING = "hex";

export async function bufferToSha1(buffer: Buffer): Promise<string> {
  const hash = crypto.createHash(HashAlgorithm.Sha1);
  const chunkSize = 100 * 1024 * 1024; // 100 MB

  return new Promise((resolve, reject) => {
    try {
      for (let offset = 0; offset < buffer.length; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, buffer.length);
        const chunk = buffer.slice(offset, end);
        hash.update(chunk);
      }

      const digest = hash.digest(HASH_ENCODING);
      resolve(digest);
    } catch (err) {
      reject(err);
    }
  });
}
