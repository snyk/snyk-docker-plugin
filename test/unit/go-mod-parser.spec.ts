import { readFileSync } from "fs";
import { join } from "path";
import { parseGoModules } from "../../lib/go-parser/go-mod-parser";

const fixturesRoot = join(__dirname, "../fixtures/go-modules");

function readFixture(relativePath: string): string {
  return readFileSync(join(fixturesRoot, relativePath), "utf8");
}

describe("go mod parser", () => {
  it("parses standard go.mod and go.sum with block and single-line requires", () => {
    const goMod = readFixture("standard/go.mod");
    const goSum = readFixture("standard/go.sum");

    const result = parseGoModules(goMod, goSum);

    expect(result.modulePath).toBe("example.com/standard");
    expect(result.dependencies).toEqual(
      expect.arrayContaining([
        { name: "github.com/gorilla/mux", version: "v1.8.0" },
        { name: "github.com/spf13/cobra", version: "v1.7.0" },
        {
          name: "github.com/inconshreveable/mousetrap",
          version: "v1.1.0",
        },
      ]),
    );
    expect(result.dependencies).toHaveLength(3);
  });

  it("applies replace directives and drops local path replacements", () => {
    const goMod = readFixture("replace/go.mod");
    const goSum = readFixture("replace/go.sum");

    const result = parseGoModules(goMod, goSum);

    expect(result.modulePath).toBe("example.com/replace");
    expect(result.dependencies).toEqual(
      expect.arrayContaining([
        { name: "github.com/new/module", version: "v2.0.0" },
        { name: "github.com/another/old", version: "v2.0.0" },
      ]),
    );
    expect(result.dependencies).toHaveLength(2);
    expect(result.dependencies).not.toEqual(
      expect.arrayContaining([
        { name: "github.com/old/module", version: "v1.0.0" },
        { name: "github.com/local/drop", version: "v1.0.0" },
      ]),
    );
  });

  it("parses go.mod without go.sum", () => {
    const goMod = readFixture("no-sum/go.mod");

    const result = parseGoModules(goMod);

    expect(result.modulePath).toBe("example.com/no-sum");
    expect(result.dependencies).toEqual(
      expect.arrayContaining([
        { name: "github.com/stretchr/testify", version: "v1.8.0" },
        { name: "github.com/davecgh/go-spew", version: "v1.1.1" },
      ]),
    );
    expect(result.dependencies).toHaveLength(2);
  });

  it("does not throw on malformed go.mod and go.sum", () => {
    const goMod = readFixture("malformed/go.mod");
    const goSum = readFixture("malformed/go.sum");

    expect(() => parseGoModules(goMod, goSum)).not.toThrow();

    const result = parseGoModules(goMod, goSum);

    expect(result.modulePath).toBe("example.com/malformed");
    expect(result.dependencies).toEqual(
      expect.arrayContaining([
        { name: "github.com/good/module", version: "v1.0.0" },
        { name: "github.com/also/good", version: "v2.0.0" },
        { name: "github.com/block/good", version: "v3.0.0" },
      ]),
    );
    expect(result.dependencies).toHaveLength(3);
  });
});
