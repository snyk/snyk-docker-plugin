import { Buffer } from "buffer";
import * as crypto from "crypto";

import { bufferToSha1 } from "../../lib/buffer-utils";

describe("buffer-utils", () => {
  describe("bufferToSha1", () => {
    it("should convert Buffer to sha1", async () => {
      // Arrange
      const textToConvert = "hello world";
      let hashedText = crypto.createHash("sha1");
      hashedText.setEncoding("hex");
      hashedText.update(textToConvert);
      hashedText.end();
      hashedText = hashedText.read().toString("hex");

      const bufferedText = Buffer.from(textToConvert);

      // Act
      const result = await bufferToSha1(bufferedText);

      // Assert
      expect(result).toEqual(hashedText);
    });

    xit("should handle large files", async () => {
      const megabyte = 1024 * 1024;
      const gigabyte = megabyte * 1024;

      // create a buffer representing a file over 2GB, which would throw
      // a RangeError if using the update method of a Crypto.Hash object,
      // instead of the streaming interface which allows us to support
      // large files
      const buffer = Buffer.concat([
        Buffer.alloc(gigabyte * 2),
        Buffer.alloc(megabyte),
      ]);
      const digest = await bufferToSha1(buffer);
      expect(digest).toEqual(expect.any(String));
    });
  });
});
