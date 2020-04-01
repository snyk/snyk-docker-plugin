import * as crypto from "crypto";
import { Readable } from "stream";

export const HASH_ALGORITHM_SHA1 = "sha1";
export const HASH_ALGORITHM_SHA256 = "sha256";
export const HASH_ENCODING = "hex";

export async function streamToString(
  stream: Readable,
  encoding: string = "utf8",
): Promise<string> {
  const chunks: string[] = [];
  return new Promise((resolve, reject) => {
    stream.on("end", () => {
      resolve(chunks.join(""));
    });
    stream.on("error", (error) => reject(error));
    stream.on("data", (chunk) => {
      chunks.push(chunk.toString(encoding));
    });
  });
}

export async function streamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    stream.on("end", () => {
      resolve(Buffer.concat(chunks));
    });
    stream.on("error", (error) => reject(error));
    stream.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk));
    });
  });
}

export async function streamToHashSHA1(stream: Readable): Promise<string> {
  return doStreamToHash(stream, HASH_ALGORITHM_SHA1, HASH_ENCODING);
}

export async function streamToHashSHA256(stream: Readable): Promise<string> {
  return doStreamToHash(stream, HASH_ALGORITHM_SHA256, HASH_ENCODING);
}

async function doStreamToHash(
  stream: Readable,
  hashAlgo: string,
  hashEnc: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(hashAlgo);
    hash.setEncoding(hashEnc);

    stream.on("end", () => {
      hash.end();
      resolve(hash.read());
    });

    stream.on("error", (error) => reject(error));

    stream.pipe(hash);
  });
}
