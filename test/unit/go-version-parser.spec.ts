import * as elf from "elfy";
import * as fs from "fs";
import { join as pathJoin } from "path";
import { FileContent } from "../../lib/extractor/types";
import { Elf } from "../../lib/go-parser/types";
import { extractModulesFromBinary } from "../../lib/go-parser/version-parser";

describe("go binary version parser", () => {
  const files = fs.readdirSync(pathJoin(__dirname, "../fixtures/go-binaries"));
  for (const file of files) {
    it(`parse go binary ${file}`, async () => {
      const fileContent = fs.readFileSync(
        pathJoin(__dirname, "../fixtures/go-binaries", file),
      );
      const binary = elf.parse(fileContent) as any;
      if (isElfType(binary)) {
        const res = extractModulesFromBinary(binary as Elf);
        expect(res.goVersion).toEqual(file);
        expect(res.modules).toMatchObject({
          "github.com/gorilla/mux": "1.8.0",
          "github.com/ghodss/yaml": "1.0.0",
          "github.com/go-redis/redis/v9": "#beta.1",
        });
      }
    });
  }
});

function isElfType(type: FileContent): type is Elf {
  const elf = type as Elf;
  return !!(elf.body && elf.body.programs && elf.body.sections);
}
