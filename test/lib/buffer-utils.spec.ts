import { Buffer } from "buffer";
import * as crypto from "crypto";
import { bufferToSha1 } from "../../lib/buffer-utils";

describe("buffer-utils", () => {
  describe("bufferToSha1", () => {
    it("should convert Buffer to sha1", () => {
      // Arrange
      const textToConvert = "hello world";
      let hashedText = crypto.createHash("sha1");
      hashedText.setEncoding("hex");
      hashedText.update(textToConvert);
      hashedText.end();
      hashedText = hashedText.read().toString("hex");

      const bufferedText = Buffer.from(textToConvert);

      // Act
      const result = bufferToSha1(bufferedText);

      // Assert
      expect(result).toEqual(hashedText);
    });
  });
});
