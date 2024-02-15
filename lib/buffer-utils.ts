import * as crypto from "crypto";
import { Readable } from "stream";
import { HashAlgorithm } from "./types";

const HASH_ENCODING = "hex";

export async function bufferToSha1(buffer: Buffer): Promise<string> {
  const stream = Readable.from(buffer);
  const hash = crypto.createHash(HashAlgorithm.Sha1);

  return new Promise((resolve, reject) => {
    stream
      .pipe(hash)
      .on("finish", () => {
        hash.end();
        const digest = hash.read().toString(HASH_ENCODING);
        resolve(digest);
      })
      .on("error", (err) => {
        reject(err);
      });
  });
}
