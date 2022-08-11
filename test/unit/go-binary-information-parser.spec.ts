import * as elf from "elfy";
import * as fs from "fs";
import { join as pathJoin } from "path";

import { FileContent } from "../../lib/extractor/types";
import { readFilesFromPCLNTable } from "../../lib/go-parser";
import { Elf } from "../../lib/go-parser/types";
import { extractModulesFromBinary } from "../../lib/go-parser/version-parser";

// contains all test cases for the PCLN Tab / Symbol table parser.
// Some general notes about this:
// - We test with three different versions, 1.13, 1.16 and 1.18, because the PCLN Tab has different formats for 1.2 -
//   1.15, 1.16-1.17 and 1.18-<current>. We're using 1.13 instead of 1.2 because 1.2 is really old and 1.13 is the
//   minimum requirement for most modules (this is when module-support landed).
//   For every version we make sure that a file exists that is only compiled at that version, meaning it should not be
//   present in other versions. These are the following files:
//   1.13: `/usr/local/go/src/vendor/golang.org/x/crypto/curve25519/doc.go`
//   1.16: `/usr/local/go/src/io/ioutil/tempfile.go`
//   1.18: `/usr/local/go/src/unicode/casetables.go`
// - We also build "latest" binaries from time to time to ensure compatibility with newly released Go Versions.
//   These tests do not have an "expectedFilesTotal" set because this may change from version to version.
//   They're also only executed if the files exist, which means that they will not be triggered when executing a normal
//   unit-test. The binaries have to be built first.
// - There's always a normal test and at least one test including cgo, stripped and trimmed.
//   - CGo means the binary had some C code in it and was also linked against C binaries. Built with `CGO_ENABLED=1`.
//     For CGo test cases, we always expect a `_cgo_gotypes.go` file to be present, plus the `net/cgo_unix.go` file
//     instead of `net/cgo_stub.go`.
//   - Trimmed means that the file paths have been trimmed with the `-trimpath` flag to `go build`.
//   - Stripped means that the debug symbols have been stripped away with the `-ldflags="-s -w"` flag to `go build`.
// - The binaries have been generated from the `build.sh` script that is located within
//    /test/fixtures/go-binaries/source. To add a new version, add it to the build.sh script and execute it. The Go
//    source files is also located in that directory.
const testCases = {
  "go1.13.15_normal": {
    expectedFilesTotal: 519,
    expectedFiles: [
      "/usr/local/go/src/time/zoneinfo.go",
      "/usr/local/go/src/os/executable_procfs.go",
      "/usr/local/go/src/io/io.go",
      "/go/pkg/mod/github.com/ghodss/yaml@v1.0.0/yaml.go",
      "/app/main.go",
      "/go/pkg/mod/github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "/usr/local/go/src/net/cgo_stub.go",
      "/usr/local/go/src/vendor/golang.org/x/crypto/curve25519/doc.go",
    ],
  },
  "go1.13.15_cgo_trimmed_stripped": {
    expectedFilesTotal: 523,
    expectedFiles: [
      "time/zoneinfo.go",
      "os/executable_procfs.go",
      "io/io.go",
      "github.com/ghodss/yaml@v1.0.0/yaml.go",
      "symboltest@/main.go",
      "github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "net/cgo_unix.go",
      "_cgo_gotypes.go",
      "vendor/golang.org/x/crypto/curve25519/doc.go",
    ],
  },
  "go1.16_15_normal": {
    expectedFilesTotal: 506,
    expectedFiles: [
      "/usr/local/go/src/os/executable_procfs.go",
      "/usr/local/go/src/io/io.go",
      "/go/pkg/mod/github.com/ghodss/yaml@v1.0.0/yaml.go",
      "/app/main.go",
      "/go/pkg/mod/github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "/usr/local/go/src/net/cgo_stub.go",
      "/usr/local/go/src/io/ioutil/tempfile.go",
    ],
  },
  "go1.16.15_cgo_trimmed_stripped": {
    expectedFilesTotal: 510,
    expectedFiles: [
      "os/executable_procfs.go",
      "io/io.go",
      "github.com/ghodss/yaml@v1.0.0/yaml.go",
      "symboltest/main.go",
      "github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "net/cgo_unix.go",
      "_cgo_gotypes.go",
      "io/ioutil/tempfile.go",
    ],
  },
  "go1.18.5_normal": {
    expectedFilesTotal: 538,
    expectedFiles: [
      "/usr/local/go/src/unicode/casetables.go",
      "/usr/local/go/src/os/dir.go",
      "/usr/local/go/src/io/io.go",
      "/go/pkg/mod/github.com/ghodss/yaml@v1.0.0/yaml.go",
      "/app/main.go",
      "/go/pkg/mod/github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "/usr/local/go/src/net/cgo_stub.go",
    ],
  },
  "go1.18.5_cgo_trimmed_stripped": {
    expectedFilesTotal: 542,
    expectedFiles: [
      "unicode/casetables.go",
      "io/io.go",
      "github.com/ghodss/yaml@v1.0.0/yaml.go",
      "symboltest/main.go",
      "github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "net/cgo_unix.go",
      "runtime/cgo/asm_amd64.s",
      "_cgo_gotypes.go",
    ],
  },
  latest_normal: {
    expectedFiles: [
      "/usr/local/go/src/unicode/casetables.go",
      "/usr/local/go/src/os/dir.go",
      "/usr/local/go/src/io/io.go",
      "/go/pkg/mod/github.com/ghodss/yaml@v1.0.0/yaml.go",
      "/app/main.go",
      "/go/pkg/mod/github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
    ],
  },
  latest_stripped: {
    expectedFiles: [
      "/usr/local/go/src/unicode/casetables.go",
      "/usr/local/go/src/io/io.go",
      "/go/pkg/mod/github.com/ghodss/yaml@v1.0.0/yaml.go",
      "/app/main.go",
      "/go/pkg/mod/github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
    ],
  },
  latest_cgo: {
    expectedFiles: [
      "/usr/local/go/src/unicode/casetables.go",
      "/usr/local/go/src/io/io.go",
      "/go/pkg/mod/github.com/ghodss/yaml@v1.0.0/yaml.go",
      "/app/main.go",
      "/go/pkg/mod/github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "/usr/local/go/src/net/cgo_unix.go",
      "/usr/local/go/src/runtime/cgo/asm_amd64.s",
      "_cgo_gotypes.go",
    ],
  },
  latest_cgo_trimmed_stripped: {
    expectedFiles: [
      "unicode/casetables.go",
      "io/io.go",
      "github.com/ghodss/yaml@v1.0.0/yaml.go",
      "symboltest/main.go",
      "github.com/go-redis/redis/v9@v9.0.0-beta.2/redis.go",
      "net/cgo_unix.go",
      "runtime/cgo/asm_amd64.s",
      "_cgo_gotypes.go",
    ],
  },
};

describe("go symbols parser", () => {
  const files = fs.readdirSync(pathJoin(__dirname, "../fixtures/go-binaries"), {
    withFileTypes: true,
  });
  for (const file of files) {
    if (!file.isFile()) {
      continue;
    }
    const fileContent = fs.readFileSync(
      pathJoin(__dirname, "../fixtures/go-binaries/", file.name),
    );
    const binary = elf.parse(fileContent) as any;
    expect(isElfType(binary)).toBe(true);

    it(`extract go version and modules from binary: ${file.name}`, async () => {
      const res = extractModulesFromBinary(binary as Elf);
      const expectedVersion = goVersionFromFileName(file.name);
      if (expectedVersion !== "latest") {
        expect(res.goVersion).toEqual(expectedVersion);
      }
      expect(res.modules).toMatchObject({
        "github.com/gorilla/mux": "1.8.0",
        "github.com/ghodss/yaml": "1.0.0",
        "github.com/go-redis/redis/v9": "#beta.2",
      });
    });

    if (testCases.hasOwnProperty(file.name)) {
      const testCase = testCases[file.name];
      it(`extract Go files from binary: ${file.name}`, async () => {
        const pclnTab = binary.body.sections.find(
          (section) => section.name === ".gopclntab",
        );

        const files = readFilesFromPCLNTable(pclnTab.data);
        if (testCase.expectedFilesTotal !== undefined) {
          expect(files).toHaveLength(testCase.expectedFilesTotal);
        }
        expect(files).toEqual(expect.arrayContaining(testCase.expectedFiles));
      });
    }
  }
});

function isElfType(type: FileContent): type is Elf {
  const elf = type as Elf;
  return !!(elf.body && elf.body.programs && elf.body.sections);
}

// goVersionFromFileName returns the go version from a filename.
// The expected format of a file name is <go Version>_<suffix>.
// It also matches Go's behaviour of trimming trailing ".0"s,
// meaning "1.19.0" is reported as "1.19".
function goVersionFromFileName(name: string): string {
  const parts = name.split("_", 2);
  return parts[0].replace(/\.0$/, "");
}
