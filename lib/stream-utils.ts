import * as crypto from "crypto";
import { Readable } from "stream";
import { HashAlgorithm } from "./types";

const HASH_ENCODING = "hex";
const MEGABYTE = 1 * 1024 * 1024;

/**
 * https://nodejs.org/api/buffer.html#buffer_buffers_and_character_encodings
 */
type SupportedEncodings = "utf8" | "base64";

export async function streamToString(
  stream: Readable,
  streamSize?: number,
  encoding: SupportedEncodings = "utf8",
): Promise<string> {
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    stream.on("end", () => {
      resolve(Buffer.concat(chunks).toString(encoding));
    });
    stream.on("error", (error) => reject(error));
    stream.on("data", (chunk) => {
      chunks.push(chunk);
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

async function streamToHash(
  stream: Readable,
  hashAlgorithm: string,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const hash = crypto.createHash(hashAlgorithm);
    hash.setEncoding(HASH_ENCODING);

    stream.on("end", () => {
      hash.end();
      resolve(hash.read().toString(HASH_ENCODING));
    });

    stream.on("error", (error) => reject(error));

    stream.pipe(hash);
  });
}

export async function streamToSha256(stream: Readable): Promise<string> {
  return streamToHash(stream, HashAlgorithm.Sha256);
}

export async function streamToSha1(stream: Readable): Promise<string> {
  return streamToHash(stream, HashAlgorithm.Sha1);
}

/**
 * Reads up to 2 megabytes from the stream and tries to JSON.parse the result.
 * Will reject if an error occurs from within the stream or when parsing cannot be done.
 */
export async function streamToJson<T>(stream: Readable): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const chunks: string[] = [];
    let bytes = 0;
    stream.on("end", () => {
      try {
        resolve(JSON.parse(chunks.join("")));
      } catch (error) {
        reject(error);
      }
    });
    stream.on("error", (error) => reject(error));
    stream.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes <= 2 * MEGABYTE) {
        chunks.push(chunk.toString("utf8"));
      } else {
        reject(new Error("The stream is too large to parse as JSON"));
      }
    });
  });
}
