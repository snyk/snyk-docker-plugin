import * as crypto from "crypto";
import { Readable } from "stream";

const HASH_ALGORITHM = "sha256"; // TODO algorithm?
const HASH_ENCODING = "hex";

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

export async function streamToHash(stream: Readable): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(HASH_ALGORITHM);
    hash.setEncoding(HASH_ENCODING);

    stream.on("end", () => {
      hash.end();
      resolve(hash.read());
    });

    stream.on("error", (error) => reject(error));

    stream.pipe(hash);
  });
}

export async function streamToJson<T>(stream: Readable): Promise<T> {
  const file = await streamToString(stream);
  return JSON.parse(file);
}
