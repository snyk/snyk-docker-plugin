import * as varint from "varint";
import {
  Elf,
  ElfProgram,
  GoModulesResult,
  GoVersionsResult,
  ReadPtrFunc,
} from "./types";

/**
 * Create same output as `go version -m binary-file` does
 * @param binary
 */
export function extractModulesFromBinary(binary: Elf): GoModulesResult {
  const { version: goVersion, mod } = findVers(binary);
  const { name, modules } = prepareGoDependencies(mod);

  return { goVersion, name, modules };
}

/**
 * Normalize versions to align with `snyk-go-parser`
 * @param mod
 */
function prepareGoDependencies(
  mod: string,
): Omit<GoModulesResult, "goVersion"> {
  if (!mod) {
    return { name: "", modules: {} };
  }

  const [, mainModuleLine, ...versionsLines] = mod.split("\n");
  const [, name] = mainModuleLine.split("\t");
  const modules = {};
  versionsLines.forEach((versionLine) => {
    if (!versionLine) {
      return;
    }
    const [, name, ver] = versionLine.split("\t");
    if (!name || !ver) {
      return;
    }
    // Versions in Go have leading 'v'
    let version = ver.substring(1);
    // In versions with hash, we only care about hash
    // v0.0.0-20200905004654-be1d3432aa8f => #be1d3432aa8f
    version = version.includes("-")
      ? `#${version.substring(version.lastIndexOf("-") + 1)}`
      : version;

    modules[name] = version;
  });

  return { name, modules };
}

// Source
// https://github.com/golang/go/blob/master/src/debug/buildinfo/buildinfo.go#L142
/**
 * Function finds and returns the Go version and
 * module version information in the executable binary
 * @param binary
 */
function findVers(binary: Elf): GoVersionsResult {
  const buildInfoMagic = "\xff Go buildinf:";
  const result = {
    version: "",
    mod: "",
  };
  // Read the first 64kB of dataAddr to find the build info blob.
  // On some platforms, the blob will be in its own section, and DataStart
  // returns the address of that section. On others, it's somewhere in the
  // data segment; the linker puts it near the beginning.
  const dataAddr = dataStart(binary);
  let data =
    readData(binary.body.programs, dataAddr, 64 * 1024) || Buffer.from([]);

  const buildInfoAlign = 16;
  const buildInfoSize = 32;

  while (true) {
    const i = data.toString("binary").indexOf(buildInfoMagic);
    if (i < 0 || data.length - i < buildInfoSize) {
      return result;
    }
    if (i % buildInfoAlign === 0 && data.length - i >= buildInfoSize) {
      data = data.subarray(i);
      break;
    }
    data = data.subarray((i + buildInfoAlign - 1) & ~buildInfoAlign);
  }

  // Decode the blob.
  // The first 14 bytes are buildInfoMagic.
  // The next two bytes indicate pointer size in bytes (4 or 8) and endianness
  // (0 for little, 1 for big).
  // Two virtual addresses to Go strings follow that: runtime.buildVersion,
  // and runtime.modinfo.
  // On 32-bit platforms, the last 8 bytes are unused.
  // If the endianness has the 2 bit set, then the pointers are zero
  // and the 32-byte header is followed by varint-prefixed string data
  // for the two string values we care about.
  const ptrSize = data[14];
  if ((data[15] & 2) !== 0) {
    data = data.subarray(32);
    [result.version, data] = decodeString(data);
    [result.mod, data] = decodeString(data);
  } else {
    const bigEndian = data[15] !== 0;

    let readPtr: ReadPtrFunc;
    if (ptrSize === 4) {
      if (bigEndian) {
        readPtr = (buffer) => buffer.readUInt32BE(0);
      } else {
        readPtr = (buffer) => buffer.readUInt32LE(0);
      }
    } else {
      if (bigEndian) {
        readPtr = (buffer) => Number(buffer.readBigUInt64BE());
      } else {
        readPtr = (buffer) => Number(buffer.readBigUInt64LE());
      }
    }

    // The build info blob left by the linker is identified by
    // a 16-byte header, consisting of buildInfoMagic (14 bytes),
    // the binary's pointer size (1 byte),
    // and whether the binary is big endian (1 byte).
    // Now we attempt to read info after metadata.
    // From 16th byte to 16th + ptrSize there is a header that points
    // to go version
    const version: string = readString(
      binary,
      ptrSize,
      readPtr,
      readPtr(data.slice(16, 16 + ptrSize)),
    );

    if (version === "") {
      return result;
    }

    result.version = version;

    // Go version header was right after metadata.
    // Modules header right after go version
    // Read next `ptrSize` bytes, this point to the
    // place where modules info is stored
    const mod: string = readString(
      binary,
      ptrSize,
      readPtr,
      readPtr(data.slice(16 + ptrSize, 16 + 2 * ptrSize)),
    );

    // This verifies that what we got are actually go modules
    // First 16 bytes are unicodes as last 16
    // Mirrors go version source code
    if (mod.length >= 33 && mod[mod.length - 17] === "\n") {
      result.mod = mod.slice(16, mod.length - 16);
    } else {
      result.mod = "";
    }
  }
  return result;
}

function decodeString(data: Buffer): [string, Buffer] {
  const num = varint.decode(data);
  const size = varint.decode.bytes;
  if (size <= 0 || num >= data.length - size) {
    return ["", Buffer.from([])];
  }
  const res = data.subarray(size, num + size);
  const rest = data.subarray(num + size);
  return [res.toString("binary"), rest];
}

// Source
// https://github.com/golang/go/blob/46f99ce7ea97d11b0a1a079da8dda0f51df2a2d2/src/cmd/go/internal/version/exe.go#L105
/**
 * Find start of section that contains module version data
 * @param binary
 */
function dataStart(binary: Elf): number {
  for (const section of binary.body.sections) {
    if (section.name === ".go.buildinfo") {
      return section.addr;
    }
  }

  for (const program of binary.body.programs) {
    if (program.type === "load" && program.flags.w === true) {
      return program.vaddr;
    }
  }

  return 0;
}

// Source
// https://github.com/golang/go/blob/46f99ce7ea97d11b0a1a079da8dda0f51df2a2d2/src/cmd/go/internal/version/exe.go#L87
/**
 * Read at most `size` of bytes from `program` that contains byte at `addr`
 * @param programs
 * @param addr
 * @param size
 */
function readData(
  programs: ElfProgram[],
  addr: number,
  size: number,
): Buffer | undefined {
  for (const program of programs) {
    const vaddr = program.vaddr;
    const filesz = program.filesz;
    if (vaddr <= addr && addr <= vaddr + filesz - 1) {
      let n = vaddr + filesz - addr;

      if (n > size) {
        n = size;
      }

      const from = addr - vaddr; // offset from the beginning of the program

      return program.data.slice(from, from + n);
    }
  }

  return undefined;
}

// Source
// https://github.com/golang/go/blob/46f99ce7ea97d11b0a1a079da8dda0f51df2a2d2/src/cmd/go/internal/version/version.go#L189
/**
 * Function returns the string at address addr in the executable x
 * @param binaryFile
 * @param ptrSize
 * @param readPtr
 * @param addr
 */
function readString(
  binaryFile: Elf,
  ptrSize: number,
  readPtr: ReadPtrFunc,
  addr: number,
): string {
  const hdr = readData(binaryFile.body.programs, addr, 2 * ptrSize);
  if (!hdr || hdr.length < 2 * ptrSize) {
    return "";
  }

  const dataAddr = readPtr(hdr);
  const dataLen = readPtr(hdr.slice(ptrSize));

  const data = readData(binaryFile.body.programs, dataAddr, dataLen);

  if (!data || data.length < dataLen) {
    return "";
  }

  return data.toString("binary");
}
