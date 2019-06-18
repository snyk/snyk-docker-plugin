import * as md5 from "md5";
import { Readable } from "stream";

export { md5Stream, streamToString, streamToBuffer, stringToStream };

/**
 * Consume the data from the specified stream into a string
 * @param stream stream to cosume the data from
 * @param encoding encoding to use for convertinf the data to string, default "utf8"
 * @returns string with the data consumed from the specified stream
 */
async function streamToString(
  stream: Readable,
  encoding: string = "utf8",
): Promise<string> {
  const chunks: string[] = [];
  return new Promise((resolve, reject) => {
    stream.on("end", () => {
      resolve(chunks.join(""));
    });
    stream.on("error", reject);
    stream.on("data", (chunk) => {
      chunks.push(chunk.toString(encoding));
    });
  });
}

/**
 * Consume the data from the specified stream into a Buffer
 * @param stream stream to cosume the data from
 * @returns Buffer with the data consumed from the specified stream
 */
async function streamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    stream.on("end", () => {
      resolve(Buffer.concat(chunks));
    });
    stream.on("error", reject);
    stream.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk));
    });
  });
}

/**
 * hash the specified stream with MD5
 * @param stream a stream to hash
 * @returns the resultant MD5 hash of the given stream
 */
async function md5Stream(stream: Readable): Promise<string> {
  return md5(await streamToBuffer(stream));
}

/**
 * convert the specified string to stream
 * @param str string to convert to stream
 * @returns stream with the content of the specified string
 */
async function stringToStream(str: string): Promise<Readable> {
  const s = new Readable();
  s._read = () => {
    // do nothing
  };
  s.push(str);
  s.push(null);
  return s;
}
