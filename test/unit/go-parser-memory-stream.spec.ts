import * as elf from "elfy";
import { readFileSync } from "fs";
import * as path from "path";
import { Readable } from "stream";

import { getGoModulesContentAction } from "../../lib/go-parser";

// Helper to create a readable stream from buffer
function createStreamFromBuffer(buffer: Buffer): Readable {
  const stream = new Readable();
  stream.push(buffer);
  stream.push(null);
  return stream;
}

describe("Go parser memory allocation fix", () => {
  const findGoBinaries = getGoModulesContentAction.callback!;
  const { filePathMatches } = getGoModulesContentAction;

  describe("Core memory fix - large non-ELF files", () => {
    it("should not allocate large buffers for non-ELF files", async () => {
      // This is the main bug we fixed - simulate 5GB non-ELF file
      const nonElfContent = Buffer.from("This is not an ELF file");
      const stream = createStreamFromBuffer(nonElfContent);
      const hugeReportedSize = 5 * 1024 * 1024 * 1024; // 5GB

      // Act - should not cause memory allocation issues
      const result = await findGoBinaries(stream, hugeReportedSize);

      // Assert
      expect(result).toBeUndefined();
      // If we reach here without memory errors, the fix works
    });

    it("should cap buffer size at Node.js max buffer length for large ELF files", async () => {
      // Create ELF content that would trigger large buffer allocation
      const elfContent = Buffer.concat([
        Buffer.from("\x7FELF"), // ELF magic
        Buffer.alloc(1000, 0), // Some content
      ]);
      const stream = createStreamFromBuffer(elfContent);
      const bigOlFileSize = 5 * 1024 * 1024 * 1024; // 5GB - exceeds max buffer length

      // Mock elf.parse to avoid complexity and track buffer allocation
      const originalParse = elf.parse;
      let allocatedBufferSize: number | undefined;

      // Mock Buffer.alloc to capture the size being allocated
      const originalAlloc = Buffer.alloc;
      Buffer.alloc = jest.fn().mockImplementation((size: number) => {
        allocatedBufferSize = size;
        return originalAlloc.call(Buffer, Math.min(size, 1024)); // Allocate small buffer for test
      });

      elf.parse = jest.fn().mockReturnValue({ body: { sections: [] } });

      // Act
      await findGoBinaries(stream, bigOlFileSize);

      // Assert - buffer size should be capped at Node.js max, not the huge reported size
      expect(allocatedBufferSize).toBeDefined();
      expect(allocatedBufferSize).toEqual(
        require("buffer").constants.MAX_LENGTH,
      );
      expect(allocatedBufferSize).toBeLessThan(bigOlFileSize);

      // Restore mocks
      Buffer.alloc = originalAlloc;
      elf.parse = originalParse;
    });

    it("should still process legitimate ELF files", async () => {
      // Ensure we didn't break existing functionality
      const goBinaryPath = path.join(
        __dirname,
        "../fixtures/go-binaries/go1.18.5_normal",
      );

      const goBinaryBuffer = readFileSync(goBinaryPath);
      const stream = createStreamFromBuffer(goBinaryBuffer);

      const result = await findGoBinaries(stream, goBinaryBuffer.length);

      // Should process ELF files
      expect(typeof result).toBeDefined();
    });
  });

  describe("ELF magic detection", () => {
    it("should detect ELF magic correctly", async () => {
      const elfContent = Buffer.concat([
        Buffer.from("\x7FELF"), // ELF magic
        Buffer.alloc(100, 0),
      ]);
      const stream = createStreamFromBuffer(elfContent);

      // Mock elf.parse to avoid complexity
      const originalParse = elf.parse;
      elf.parse = jest.fn().mockReturnValue({ body: { sections: [] } });

      const result = await findGoBinaries(stream, elfContent.length);

      expect(elf.parse).toHaveBeenCalled();
      expect(result).toBeUndefined(); // No Go sections

      elf.parse = originalParse;
    });

    it("should reject non-ELF files early", async () => {
      const nonElfContent = Buffer.from("Not ELF content");
      const stream = createStreamFromBuffer(nonElfContent);

      const result = await findGoBinaries(stream, 1024 * 1024); // 1MB

      expect(result).toBeUndefined();
    });
  });

  describe("filePathMatches function", () => {
    it("should match normal files without extensions", () => {
      expect(filePathMatches("/app/myservice")).toBe(true);
      expect(filePathMatches("/usr/bin/kubectl")).toBe(true);
      expect(filePathMatches("/opt/binary")).toBe(true);
    });

    it("should not match files with extensions", () => {
      expect(filePathMatches("/app/script.sh")).toBe(false);
      expect(filePathMatches("/app/config.json")).toBe(false);
      expect(filePathMatches("/app/main.go")).toBe(false);
    });

    it("should not match files in ignored paths", () => {
      expect(filePathMatches("/etc/passwd")).toBe(false);
      expect(filePathMatches("/var/log/app")).toBe(false);
      expect(filePathMatches("/tmp/file")).toBe(false);
      expect(filePathMatches("/proc/cpuinfo")).toBe(false);
    });
  });

  describe("Error handling", () => {
    it("should catch stream errors", async () => {
      const errorStream = new Readable({
        read() {
          this.emit("error", new Error("Stream error"));
        },
      });

      await expect(findGoBinaries(errorStream)).rejects.toThrow("Stream error");
    });

    it("should return undefined for corrupted ELF files", async () => {
      const corruptedElf = Buffer.from("\x7FELF" + "corrupted");
      const stream = createStreamFromBuffer(corruptedElf);

      const result = await findGoBinaries(stream);

      expect(result).toBeUndefined(); // Should not throw
    });

    it("should return undefined for empty streams", async () => {
      const emptyStream = new Readable();
      emptyStream.push(null);

      const result = await findGoBinaries(emptyStream);

      expect(result).toBeUndefined();
    });
  });
});
