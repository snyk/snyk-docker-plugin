import * as crypto from "crypto";
import { Readable, Writable } from "stream";
import { createGunzip, createInflate } from "zlib";
import { HashAlgorithm } from "./types";

const HASH_ENCODING = "hex";
const MEGABYTE = 1 * 1024 * 1024;
const GZIP_HEADERS_SIZE_BYTES = 3;

/**
 * https://nodejs.org/api/buffer.html#buffer_buffers_and_character_encodings
 */
type SupportedEncodings = "utf8" | "base64";

export async function streamToString(
  stream: Readable,
  streamSize?: number,
  encoding: SupportedEncodings = "utf8",
): Promise<string> {
  const chunks: string[] = [];
  return new Promise((resolve, reject) => {
    stream.on("end", () => {
      resolve(chunks.join(""));
    });
    stream.on("error", (error) => reject(error));
    stream.on("data", (chunk: Buffer) => {
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
    stream.on("data", (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes <= 2 * MEGABYTE) {
        chunks.push(chunk.toString("utf8"));
      } else {
        reject(new Error("The stream is too large to parse as JSON"));
      }
    });
  });
}

/**
 * Decompresses a source stream (if compressed) and pipes it to a destination stream.
 */
export function pipeDecompressedStream(
  source: Readable,
  destination: Writable,
): void {
  let header = Buffer.alloc(0);

  // Collect enough bytes to be able to inspect the start of the stream to understand how it is compressed.
  const bytesCollector = (chunk: Buffer) => {
    header = Buffer.concat([header, chunk]);
    if (header.length < GZIP_HEADERS_SIZE_BYTES) {
      // Continue collecting data until we have enough
      return;
    }

    // Stop collecting individual chunks of data because we will pipe the stream from now on.
    source.off("data", bytesCollector);

    if (isGzipHeader(header)) {
      const gunzip = createGunzip();
      gunzip.write(header);
      source.pipe(gunzip).pipe(destination);
    } else if (isDeflateHeader(header)) {
      const inflate = createInflate();
      inflate.write(header);
      source.pipe(inflate).pipe(destination);
    } else {
      destination.write(header);
      source.pipe(destination);
    }
  };

  source.on("data", bytesCollector);
  // If the stream was shorter than expected, we need to write what we have collected to the destination stream.
  // Otherwise we risk the destination hanging forever waiting on data.
  source.on("end", () => {
    if (header.length < GZIP_HEADERS_SIZE_BYTES) {
      destination.write(header);
      destination.emit("finish");
    }
  });
}

function isGzipHeader(buffer: Buffer): boolean {
  return buffer[0] === 0x1f && buffer[1] === 0x8b && buffer[2] === 0x08;
}

function isDeflateHeader(buffer: Buffer): boolean {
  return (
    buffer[0] === 0x78 &&
    (buffer[1] === 1 || buffer[1] === 0x9c || buffer[1] === 0xda)
  );
}
