// lineTable maps to the Go type https://pkg.go.dev/debug/gosym#LineTable
export class LineTable {
  private static go12magic = 0xfffffffb;
  private static go116magic = 0xfffffffa;
  private static go118magic = 0xfffffff0;

  // the Go type contains some exported fields, but as we don't require anything, we don't export it.
  // We only store what we require, so some fields are missing when compared to the Go implementation.
  private version: pclnVersion = pclnVersion.unknown;
  private filetab: Buffer;
  private nfiletab: number;
  private ptrsize: number;
  private binary: ByteOrder;
  private funcdata: Buffer;
  private fileMap: Map<string, number> = new Map();

  // https://pkg.go.dev/debug/gosym#NewLineTable, but only what we need to read out the files.
  constructor(b: Buffer) {
    // Check header: 4-byte magic, two zeros, pc quantum, pointer size.
    if (
      b.length < 16 ||
      b[4] !== 0 ||
      b[5] !== 0 ||
      // pc quantum
      (b[6] !== 1 && b[6] !== 2 && b[6] !== 4) ||
      // pointer size
      (b[7] !== 4 && b[7] !== 8)
    ) {
      throw new Error("unknown header format");
    }

    // determine the endianness and the PCLN Table version
    const leMagic = b.readUInt32LE(0);
    const beMagic = b.readUInt32BE(0);
    if (leMagic === LineTable.go12magic) {
      this.binary = littleEndian;
      this.version = pclnVersion.v12;
    } else if (beMagic === LineTable.go12magic) {
      this.binary = bigEndian;
      this.version = pclnVersion.v12;
    } else if (leMagic === LineTable.go116magic) {
      this.binary = littleEndian;
      this.version = pclnVersion.v116;
    } else if (beMagic === LineTable.go116magic) {
      this.binary = bigEndian;
      this.version = pclnVersion.v116;
    } else if (leMagic === LineTable.go118magic) {
      this.binary = littleEndian;
      this.version = pclnVersion.v118;
    } else if (beMagic === LineTable.go118magic) {
      this.binary = bigEndian;
      this.version = pclnVersion.v118;
    } else {
      throw new Error("unknown / unsupported Go version");
    }

    this.ptrsize = b[7];
    const uintptr = (b: Buffer): bigint => {
      if (this.ptrsize === 4) {
        return this.binary.Uint32(b);
      }
      return this.binary.Uint64(b);
    };
    const offset = (word: number): bigint => {
      return uintptr(b.slice(8 + word * this.ptrsize));
    };
    const data = (word: number): Buffer => {
      return b.slice(Number(offset(word))); // TODO: int conversion?
    };

    switch (this.version) {
      case pclnVersion.v118:
        this.nfiletab = Number(offset(1));
        this.filetab = data(5);
        this.funcdata = data(7);
        break;
      case pclnVersion.v116:
        this.nfiletab = Number(offset(1));
        this.filetab = data(4);
        this.funcdata = data(6);
        break;
      case pclnVersion.v12:
        const nfunctab = Number(this.uintptr(b.slice(8)));
        this.funcdata = b;
        const functab = b.slice(8 + this.ptrsize);
        const functabsize = (nfunctab * 2 + 1) * this.functabFieldSize();
        const fileoff = this.binary.Uint32(functab.slice(functabsize));
        this.filetab = b.slice(Number(fileoff));
        this.nfiletab = Number(this.binary.Uint32(this.filetab));
        break;
      default:
        throw new Error("unreachable");
    }
  }

  // go12MapFiles returns a list of files that have been found in the symbol table.
  // In the original Go implementation, this function takes a map and object, but
  // we don't need to construct a map and don't need the object.
  // https://cs.opensource.google/go/go/+/refs/tags/go1.18.5:src/debug/gosym/pclntab.go;l=669
  public go12MapFiles(): string[] {
    this.initFileMap();
    const files: string[] = [];
    for (const file of Object.keys(this.fileMap)) {
      files.push(file);
    }
    return files;
  }

  // uintptr returns the pointer-sized value encoded at b.
  // The pointer size is dictated by the table being read.
  private uintptr(b: Buffer): bigint {
    if (this.ptrsize === 4) {
      return BigInt(this.binary.Uint32(b));
    }
    return this.binary.Uint64(b);
  }

  // functabFieldSize returns the sivze in bytes of a single functab field.
  // https://cs.opensource.google/go/go/+/refs/tags/go1.18.5:src/debug/gosym/pclntab.go;l=377
  private functabFieldSize(): number {
    if (this.version >= pclnVersion.v118) {
      return 4;
    }
    return this.ptrsize;
  }

  // string returns a Go string found at offset.
  // https://cs.opensource.google/go/go/+/refs/tags/go1.18.5:src/debug/gosym/pclntab.go;l=372
  private string(offset: number): string {
    return this.stringFrom(this.funcdata, offset);
  }

  // initFileMap initializes the map from file name to file number.
  // We technically don't need the number, but match Go's implementation 1:1 instead.
  // https://cs.opensource.google/go/go/+/refs/tags/go1.18.5:src/debug/gosym/pclntab.go;l=641
  private initFileMap(): void {
    if (this.fileMap.size > 0) {
      return;
    }

    const files: Map<string, number> = new Map();
    if (this.version === pclnVersion.v12) {
      for (let i = 1; i < this.nfiletab; i++) {
        const fileName = this.string(
          Number(this.binary.Uint32(this.filetab.slice(4 * i))),
        );
        files[fileName] = i;
      }
    } else {
      let pos: number = 0;
      for (let i = 0; i < this.nfiletab; i++) {
        const fileName = this.stringFrom(this.filetab, pos);
        files[fileName] = pos;
        pos += fileName.length + 1;
      }
    }
    this.fileMap = files;
  }

  // stringFrom returns a Go string found at offset from a position.
  // https://cs.opensource.google/go/go/+/refs/tags/go1.18.5:src/debug/gosym/pclntab.go;l=361
  private stringFrom(arr: Buffer, offset: number): string {
    const i = arr.slice(offset).indexOf(0);
    const s = arr.slice(offset, offset + i).toString("ascii");
    return s;
  }
}

enum pclnVersion {
  unknown,
  v11,
  v12,
  v116,
  v118,
}

// this and the endianness below matches the http://godoc.org/binary package in Go.
interface ByteOrder {
  Uint32(b: Buffer): bigint;
  Uint64(b: Buffer): bigint;
}

const bigEndian = {
  Uint32(b: Buffer): bigint {
    return BigInt(b.readUInt32BE(0));
  },
  Uint64(b: Buffer): bigint {
    return b.readBigUInt64BE(0);
  },
};

const littleEndian = {
  Uint32(b: Buffer): bigint {
    return BigInt(b.readUInt32LE(0));
  },
  Uint64(b: Buffer): bigint {
    return b.readBigUInt64LE(0);
  },
};
