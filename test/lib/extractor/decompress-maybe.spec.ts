import { Readable } from "stream";
import { gzipSync } from "zlib";
import { decompressMaybe } from "../../../lib/extractor/decompress-maybe";

describe("decompressMaybe", () => {
  // Helper to consume a stream and return the result as a buffer
  const streamToBuffer = async (stream: Readable): Promise<Buffer> => {
    const chunks: Buffer[] = [];
    return new Promise((resolve, reject) => {
      stream.on("data", (chunk) => chunks.push(chunk));
      stream.on("end", () => resolve(Buffer.concat(chunks)));
      stream.on("error", reject);
    });
  };

  describe("gzip compression", () => {
    it("should decompress gzip-compressed data", async () => {
      const originalData = Buffer.from("Hello, World!");
      const compressed = gzipSync(originalData);

      const inputStream = Readable.from([compressed]);
      const outputStream = inputStream.pipe(decompressMaybe());
      const result = await streamToBuffer(outputStream);

      expect(result.toString()).toEqual(originalData.toString());
    });
  });

  describe("uncompressed data", () => {
    it("should pass through uncompressed data unchanged", async () => {
      const originalData = Buffer.from("Plain text data");

      const inputStream = Readable.from([originalData]);
      const outputStream = inputStream.pipe(decompressMaybe());
      const result = await streamToBuffer(outputStream);

      expect(result.toString()).toEqual(originalData.toString());
    });

    it("should handle JSON data (common in OCI archives)", async () => {
      const jsonData = Buffer.from('{"test": "value"}');

      const inputStream = Readable.from([jsonData]);
      const outputStream = inputStream.pipe(decompressMaybe());
      const result = await streamToBuffer(outputStream);

      expect(result.toString()).toEqual(jsonData.toString());
    });
  });

  describe("edge cases", () => {
    it("should handle empty streams", async () => {
      const inputStream = Readable.from([]);
      const outputStream = inputStream.pipe(decompressMaybe());
      const result = await streamToBuffer(outputStream);

      expect(result.length).toBe(0);
    });

    it("should handle small data chunks", async () => {
      const smallData = Buffer.from("ab");

      const inputStream = Readable.from([smallData]);
      const outputStream = inputStream.pipe(decompressMaybe());
      const result = await streamToBuffer(outputStream);

      expect(result.toString()).toEqual(smallData.toString());
    });
  });
});
