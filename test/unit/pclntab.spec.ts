import { LineTable } from "../../lib/go-parser/pclntab";

describe("LineTable", () => {
  describe("constructor", () => {
    it("rejects buffer that is too small", () => {
      const buffer = Buffer.alloc(15);
      expect(() => new LineTable(buffer)).toThrow("unknown header format");
    });

    it("rejects non-zero reserved bytes", () => {
      const buffer = Buffer.from([0, 0, 0, 0, 1, 0, 1, 4]);
      expect(() => new LineTable(buffer)).toThrow("unknown header format");
    });

    it("rejects invalid pc quantum", () => {
      const buffer = Buffer.from([0, 0, 0, 0, 0, 0, 3, 4]);
      expect(() => new LineTable(buffer)).toThrow("unknown header format");
    });

    it("rejects invalid pointer size", () => {
      const buffer = Buffer.from([0, 0, 0, 0, 0, 0, 1, 6]);
      expect(() => new LineTable(buffer)).toThrow("unknown header format");
    });

    it("rejects unknown magic number", () => {
      const buffer = Buffer.alloc(16);
      buffer.writeUInt32BE(0xdeadbeef, 0);
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      expect(() => new LineTable(buffer)).toThrow(
        "unknown / unsupported Go version",
      );
    });

    it("accepts Go 1.2 with big-endian encoding", () => {
      const buffer = Buffer.alloc(200);
      buffer.writeUInt32BE(0xfffffffb, 0);
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      // Write nfunctab at offset 8
      buffer.writeBigUInt64BE(0n, 8);

      // Write minimal fileoff data
      const functabOffset = 16;
      buffer.writeUInt32BE(100, functabOffset); // fileoff points to offset 100
      buffer.writeUInt32BE(0, 100); // nfiletab = 0

      expect(() => new LineTable(buffer)).not.toThrow();
    });

    it("accepts Go 1.16 with big-endian encoding", () => {
      const buffer = Buffer.alloc(200);
      buffer.writeUInt32BE(0xfffffffa, 0);
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      // offset(1) at position 16
      buffer.writeBigUInt64BE(0n, 16); // nfiletab

      // offset(4) at position 40
      buffer.writeBigUInt64BE(100n, 40); // filetab offset

      // offset(6) at position 56
      buffer.writeBigUInt64BE(120n, 56); // funcdata offset

      // Write empty data at those offsets
      buffer.writeUInt32BE(0, 100);

      expect(() => new LineTable(buffer)).not.toThrow();
    });

    it("accepts Go 1.18 with big-endian encoding", () => {
      const buffer = Buffer.alloc(200);
      buffer.writeUInt32BE(0xfffffff0, 0);
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      // offset(1) at position 16
      buffer.writeBigUInt64BE(0n, 16); // nfiletab

      // offset(5) at position 48
      buffer.writeBigUInt64BE(100n, 48); // filetab offset

      // offset(7) at position 64
      buffer.writeBigUInt64BE(120n, 64); // funcdata offset

      // Write empty data at those offsets
      buffer.writeUInt32BE(0, 100);

      expect(() => new LineTable(buffer)).not.toThrow();
    });

    it("accepts Go 1.20 with big-endian encoding", () => {
      const buffer = Buffer.alloc(200);
      buffer.writeUInt32BE(0xfffffff1, 0);
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      // offset(1) at position 16
      buffer.writeBigUInt64BE(0n, 16); // nfiletab

      // offset(5) at position 48
      buffer.writeBigUInt64BE(100n, 48); // filetab offset

      // offset(7) at position 64
      buffer.writeBigUInt64BE(120n, 64); // funcdata offset

      // Write empty data at those offsets
      buffer.writeUInt32BE(0, 100);

      expect(() => new LineTable(buffer)).not.toThrow();
    });
  });

  describe("go12MapFiles", () => {
    it("caches file map after first call", () => {
      const buffer = Buffer.alloc(300);
      buffer.writeUInt32LE(0xfffffffb, 0); // Go 1.2 magic
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      // Write nfunctab at offset 8
      buffer.writeBigUInt64LE(1n, 8);

      // Functab starts at offset 16
      const functabOffset = 16;
      const functabSize = 24; // (1 * 2 + 1) * 8

      // Write fileoff after functab
      buffer.writeUInt32LE(100, functabOffset + functabSize);

      // Write filetab at offset 100
      buffer.writeUInt32LE(2, 100); // nfiletab = 2
      buffer.writeUInt32LE(108, 104); // offset to filename
      buffer.write("test.go\0", 108);

      const lt = new LineTable(buffer);
      const files1 = lt.go12MapFiles();
      const files2 = lt.go12MapFiles();

      expect(files1).toContain("test.go");
      expect(files2).toEqual(files1);
    });
  });

  describe("32-bit pointer handling", () => {
    it("handles 32-bit pointers in Go 1.2", () => {
      const buffer = Buffer.alloc(200);
      buffer.writeUInt32LE(0xfffffffb, 0); // Go 1.2 magic
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 4; // 32-bit pointer size

      // Write nfunctab at offset 8 (32-bit)
      buffer.writeUInt32LE(0, 8);

      // Functab starts at offset 12 (8 + 4)
      const functabOffset = 12;
      const functabSize = 4; // (0 * 2 + 1) * 4

      // Write fileoff
      buffer.writeUInt32LE(50, functabOffset + functabSize);

      // Write nfiletab at offset 50
      buffer.writeUInt32LE(0, 50);

      const lt = new LineTable(buffer);
      expect(() => lt.go12MapFiles()).not.toThrow();
    });
  });

  describe("Go 1.18+ format", () => {
    it("handles Go 1.18 format with different offsets", () => {
      const buffer = Buffer.alloc(200);
      buffer.writeUInt32LE(0xfffffff0, 0); // Go 1.18 magic
      buffer[4] = 0;
      buffer[5] = 0;
      buffer[6] = 1;
      buffer[7] = 8;

      // offset(1) at position 16
      buffer.writeBigUInt64LE(0n, 16); // nfiletab

      // offset(5) at position 48
      buffer.writeBigUInt64LE(100n, 48); // filetab offset

      // offset(7) at position 64
      buffer.writeBigUInt64LE(120n, 64); // funcdata offset

      // Write empty data at filetab offset
      buffer.writeUInt32LE(0, 100);

      const lt = new LineTable(buffer);
      expect(() => lt.go12MapFiles()).not.toThrow();
    });
  });
});
