import * as depGraph from "@snyk/dep-graph";
import * as elf from "elfy";
import { readdirSync, readFileSync } from "fs";
import * as path from "path";

import { goModulesToScannedProjects } from "../../lib/go-parser";
import {
  determinePaths,
  extractModuleInformation,
  GoBinary,
} from "../../lib/go-parser/go-binary";
import { GoModule } from "../../lib/go-parser/go-module";
import { LineTable } from "../../lib/go-parser/pclntab";

enum moduleType {
  StandardLibrary = "/usr/local/go/src",
  Main = "/app",
  External = "/go/pkg/mod",
}

interface Module {
  name: string;
  version: string;
  // type of the module. If unset, External is assumed.
  type: moduleType;
  // list of package name to files.
  packages: Map<string, string[]>;
}

class TestCase {
  public modules: Module[];

  constructor(modules: Module[]) {
    this.modules = modules;
  }

  // files builds and returns all files for a TestCase in random order.
  // Optionally, by setting trimPath, the files will not contain the
  // build-path, Go source directory or GOMODCACHE directory.
  public files(trimPath?: boolean, vendored?: boolean): string[] {
    const files = [];
    for (const module of this.modules) {
      for (const [pkgName, pkgFiles] of module.packages.entries()) {
        for (const file of pkgFiles) {
          files.push(buildName(module, pkgName, trimPath, file, vendored));
        }
      }
    }
    // we shuffle the files to make sure our code can handle this. Go binaries
    // do not contain the list of files in ordered fashion either.
    shuffle(files);
    return files;
  }

  // goModules collects all GoModule definitions in a TestCase, excluding
  // internal modules. Does not add packages to modules.
  public goModules(): GoModule[] {
    const mods: GoModule[] = [];
    for (const module of this.modules) {
      if (!isInternalModule(module)) {
        mods.push(new GoModule(module.name, module.version));
      }
    }
    return mods;
  }

  // goModules collects all GoModule definitions in a TestCase, excluding
  // internal modules. It also populates the packages within these modules.
  public goModulesWithPackages(): GoModule[] {
    const mods: GoModule[] = [];
    for (const module of this.modules) {
      if (isInternalModule(module)) {
        continue;
      }

      const mod = new GoModule(module.name, module.version);
      for (const [pkg] of module.packages.entries()) {
        mod.packages.push(buildName(module, pkg, true));
      }
      mods.push(mod);
    }
    return mods;
  }

  public depGraphPackages(): depGraph.PkgInfo[] {
    const pkgs: depGraph.PkgInfo[] = [];
    for (const mod of this.modules) {
      if (isInternalModule(mod)) {
        continue;
      }

      for (const [pkgName] of mod.packages) {
        pkgs.push({
          name: buildName(mod, pkgName, true),
          version: mod.version,
        });
      }
    }
    return pkgs;
  }
}

function shuffle(arr: any[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
}

function isInternalModule(m: Module): boolean {
  return m.type === moduleType.StandardLibrary || m.type === moduleType.Main;
}

// buildName builds a complete file or directory name for a given module,
// potentially with a specific version, package and filename, with the option to
// trim the build paths.
function buildName(
  module: Module,
  pkgName?: string,
  trimPath?: boolean,
  fileName?: string,
  vendored?: boolean,
) {
  let name = "";
  let dirName = "";
  if (!trimPath) {
    dirName = module.type;
  }

  switch (module.type) {
    case moduleType.Main:
      // if trimPath is not set, the module does not have a "name", it's simply
      // located at the buildDir. With trimPath, the name of the main module is
      // used instead.
      if (!trimPath) {
        name = "";
      } else {
        name = module.name;
      }
      break;

    case moduleType.StandardLibrary:
      // standard library does not have a module name
      break;

    default:
      name = module.name;
      // if the dependencies are vendored, the file path does not contain the
      // module version. Similarily, we don't want to add the version if no file
      // name is given.
      if (vendored) {
        dirName = path.join(moduleType.Main, "vendor");
      } else if (fileName) {
        name += "@" + module.version;
      }
  }

  return path.join(dirName, name, pkgName || "", fileName || "");
}

function main(goVersion: GoVersion): Module {
  const main = {
    name: "symboltest",
    type: moduleType.Main,
    packages: new Map([["", ["main.go"]]]),
  } as Module;

  if (goVersion === GoVersion.Go113) {
    main.name += "@";
  }
  return main;
}

function stdlib(
  goVersion: GoVersion,
  cgo?: boolean,
  trimmed?: boolean,
): Module {
  const lib = {
    name: "stdlib",
    type: moduleType.StandardLibrary,
    packages: new Map([["io", ["io.go"]]]),
  } as Module;

  // For every version we make sure that a file exists that is only compiled at
  // that version, meaning it should not be present in other versions.
  switch (goVersion) {
    case GoVersion.Go113:
      lib.packages.set("time", ["zoneinfo.go"]);
      lib.packages.set("os", ["executable_procfs.go"]);
      lib.packages.set("vendor/golang.org/x/crypto/curve25519", ["doc.go"]);
      break;

    case GoVersion.Go116:
      lib.packages.set("os", ["executable_procfs.go"]);
      break;

    case GoVersion.Go118:
    case undefined:
      lib.packages.set("unicode", ["casetables.go"]);
      break;
  }

  if (cgo) {
    const net = lib.packages.get("net") || [];
    net.push("cgo_unix.go");
    lib.packages.set("net", net);

    // the _cgo_gotypes.go file is generated at build time and does not have an
    // associated package. For non-trimmed binaries, this still means it's full
    // filename is just "_cgo_gotypes.go". Building this exception into the
    // testcode would be more annoying than to restrict this specific file check
    // to trimmed binaries...
    if (trimmed) {
      const root = lib.packages.get("") || [];
      root.push("_cgo_gotypes.go");
      lib.packages.set("", root);
    }
  }
  return lib;
}

// We test with three different versions, 1.13, 1.16 and 1.18, because the
// PCLN Tab has different formats for 1.2 - 1.15, 1.16-1.17 and 1.18-<current>.
// We're using 1.13 instead of 1.2 because 1.2 is really old and 1.13 is the
// minimum requirement for most modules (this is when module-support landed).
enum GoVersion {
  Go113,
  Go116,
  Go118,
}

function extractGoVersion(fileName: string): GoVersion {
  // we're using the fact that "go1.nn" has the same length as "latest"
  const vers = path.parse(fileName).name.substring(0, 7);
  switch (vers) {
    case "go1.13":
      return GoVersion.Go113;
    case "go1.16":
      return GoVersion.Go116;
    case "go1.18":
      return GoVersion.Go118;
    default:
      // if the test fails because we're using GoVersion.Go118 here, it means
      // that the binary format has changed and we need to introduce a new
      // version + check how to handle that.
      return GoVersion.Go118;
  }
}

describe("test from binaries", () => {
  const files = readdirSync(path.join(__dirname, "../fixtures/go-binaries"));
  for (const file of files) {
    if (!file.match(/^go1\.[0-9]{1,2}\.[0-9]{1,2}_.*/)) {
      continue;
    }

    describe(`handles file ${file}`, () => {
      const fileContent = readFileSync(
        path.join(__dirname, "../fixtures/go-binaries/", file),
      );
      const goVersion = extractGoVersion(file);
      const isTrimmed = file.includes("trimmed");
      const isVendored = file.includes("vendored");
      const isCGo = file.includes("cgo");

      const testCase = new TestCase([
        stdlib(goVersion, isCGo, isTrimmed),
        main(goVersion),
        {
          name: "github.com/go-redis/redis/v9",
          version: "v9.0.0-beta.2",
          type: moduleType.External,
          packages: new Map([
            // exhaustive package list, but non-exhaustive file list in each
            // package.
            ["", ["error.go", "cluster.go", "options.go"]],
            ["internal", ["unsafe.go", "log.go", "util.go"]],
            ["internal/hscan", ["hscan.go"]],
            ["internal/pool", ["pool.go", "conn.go"]],
            ["internal/proto", ["writer.go", "reader.go"]],
            ["internal/rand", ["rand.go"]],
            ["internal/util", ["strconv.go"]],
          ]),
        },
        {
          name: "github.com/ghodss/yaml",
          version: "v1.0.0",
          type: moduleType.External,
          packages: new Map([["", ["yaml.go"]]]),
        },
        // These dependencies are listed in the Go binary
        // (`go version -m <binary>` will report it), but no files or packages
        // are included in the build. I assume that these module are simply
        // required to resolve other module versions, and are included in the
        // build so that users are able to reproduce the dependency list as
        // well.
        {
          name: "github.com/cespare/xxhash/v2",
          version: "v2.1.2",
          type: moduleType.External,
          packages: new Map(),
        },
        {
          name: "github.com/dgryski/go-rendezvous",
          version: "v0.0.0-20200823014737-9f7001d12a5f",
          type: moduleType.External,
          packages: new Map(),
        },
      ]);

      const elfBinary = elf.parse(fileContent);
      const goBin = new GoBinary(elfBinary);

      // ensures that we find all expected *modules* in the binaries.
      it(`extracts go modules from binary`, () => {
        const [, modules] = extractModuleInformation(elfBinary);
        testCase.goModules().forEach((module) => {
          expect(modules).toContainEqual(module);
        });
      });

      // ensures that we find all expected *files* in the binaries.
      it(`extracts correct files from binary`, () => {
        const pclnTab = elfBinary.body.sections.find(
          (section) => section.name === ".gopclntab",
        );

        const files = new LineTable(pclnTab.data).go12MapFiles();
        expect(files).toEqual(
          expect.arrayContaining(testCase.files(isTrimmed, isVendored)),
        );
      });

      // ensures that we map the files correctly to packages.
      it(`extracts modules and packages from binary`, () => {
        goBin.modules.forEach((module: GoModule) => {
          module.packages.sort();
        });

        testCase.goModulesWithPackages().forEach((module) => {
          expect(goBin.modules).toContainEqual(module);
        });
      });

      // ensures that the returned dependency graph contains all packages with
      // the correctly normalized versions.
      it(`generates the correct dep graph`, async () => {
        const depGraph = await goBin.depGraph();
        const pkgs = depGraph.getPkgs();
        testCase.depGraphPackages().forEach((pkg) => {
          expect(pkgs).toContainEqual(pkg);
        });
      });

      // ensures that the mapping process is correct on arbitrary data. For this
      // test, we update the read binary with some fake data. Because this
      // *modifies* the binary and the testcase object, this test needs to be
      // last in order.
      it(`matches files to packages`, () => {
        // make the file to package matching test a bit more exhaustive by
        // testing multiple different cases in a single module:
        // - a package at the root of the module
        // - package with subpackages
        // - package with multiple files.
        testCase.modules.push({
          name: "github.com/my/test",
          version: "v0.1.0",
          type: moduleType.External,
          packages: new Map([
            ["", ["test.go"]],
            ["pkg/a", ["a.go"]],
            ["pkg/a/a", ["a.go"]],
            ["pkg/a/b", ["b.go"]],
            ["pkg/b", ["a.go", "b.go", "c.go"]],
          ]),
        });
        goBin.modules = testCase.goModules();
        goBin.matchFilesToModules(testCase.files());

        // we need to sort all packages because toEqual compares the
        // order of the subarrays.
        goBin.modules.forEach((module: GoModule) => {
          module.packages.sort();
        });
        expect(goBin.modules).toEqual(testCase.goModulesWithPackages());
      });
    });
  }
});

describe("test stdlib bin project name", () => {
  it("has correct project name even if mod directive is missing", () => {
    const goBin = new GoBinary(
      elf.parse(
        readFileSync(
          path.join(__dirname, "../fixtures/go-binaries/stdlib_pack"),
        ),
      ),
    );
    expect(goBin.name).toBe("go-distribution@cmd/pack");
    // binaries from the standard library usually don't have external deps.
    expect(goBin.modules).toHaveLength(0);
  });
});

describe("test binary without pcln table", () => {
  it("does not fail if Go binary does not contain PCLN table", async () => {
    const fileName = path.join(
      __dirname,
      "../fixtures/go-binaries/no-pcln-tab",
    );
    await expect(
      goModulesToScannedProjects({
        fileName: elf.parse(readFileSync(fileName)),
      }),
    ).resolves.not.toThrow();
  });
});

// The Go stdlib contains a vendored module, `golang.org/x/net`. If a binary
// depends on that module as well, and is built with `-trimpath`, there will be
// two different modules & files in the binary metadata, e.g.:
// - vendor/golang.org/x/net/http/httpguts/guts.go
// - golang.org/x/net/http/httpguts/guts.go.
// We want to make sure this still works.
describe("test stdlib vendor", () => {
  it("finds the right dependencies", async () => {
    const fileName = path.join(
      __dirname,
      "../fixtures/go-binaries/fake-vendor",
    );
    const graph = await new GoBinary(
      elf.parse(readFileSync(fileName)),
    ).depGraph();

    expect(graph.getPkgs()).toContainEqual({
      name: "golang.org/x/net/http/httpguts",
      version: "v0.1.0",
    });
    expect(graph.getPkgs()).toContainEqual({
      name: "github.com/spf13/cobra",
      version: "v1.6.1",
    });
    expect(graph.rootPkg.name).toBe("github.com/myrepo/partvend");
  });
});

describe("test path determination", () => {
  it("finds the right paths with mix of vendor and normal", () => {
    const modules = [
      new GoModule("github.com/dep/a", "v0.0.1"),
      new GoModule("github.com/dep/b", "v0.1.0"),
    ];
    const files = [
      "/project/main.go",
      "/project/pkg/pkg.go",
      "/project/vendor/github.com/dep/b/pkg/b.go",
      "/go/pkg/mod/cache/github.com/dep/a@v0.0.1/a.go",
      "/usr/local/go/src/fmt/fmt.go",
      "/usr/local/go/src/net/net.go",
      "/usr/local/go/src/vendor/golang.org/x/net/net.go",
    ];

    const { modCachePath, vendorPath } = determinePaths(modules, files);
    expect(modCachePath).toBe("/go/pkg/mod/cache/");
    expect(vendorPath).toBe("/project/vendor/");
  });

  it("finds the right paths with only vendored", () => {
    const modules = [
      new GoModule("github.com/dep/a", "v0.0.1"),
      new GoModule("github.com/dep/b", "v0.1.0"),
    ];
    const files = [
      "/project/main.go",
      "/project/pkg/pkg.go",
      "/project/vendor/github.com/dep/b/pkg/b.go",
      "/project/vendor/github.com/dep/a/a.go",
      "/usr/local/go/src/fmt/fmt.go",
      "/usr/local/go/src/net/net.go",
      "/usr/local/go/src/vendor/golang.org/x/net/net.go",
    ];

    const { modCachePath, vendorPath } = determinePaths(modules, files);
    expect(modCachePath).toBe("");
    expect(vendorPath).toBe("/project/vendor/");
  });
  it("finds the right paths with only normal", () => {
    const modules = [
      new GoModule("github.com/dep/a", "v0.0.1"),
      new GoModule("github.com/dep/b", "v0.1.0"),
    ];
    const files = [
      "/project/main.go",
      "/project/pkg/pkg.go",
      "/go/pkg/mod/cache/github.com/dep/b@v0.1.0/pkg/b.go",
      "/go/pkg/mod/cache/github.com/dep/a@v0.0.1/a.go",
      "/usr/local/go/src/fmt/fmt.go",
      "/usr/local/go/src/net/net.go",
      "/usr/local/go/src/vendor/golang.org/x/net/net.go",
    ];

    const { modCachePath, vendorPath } = determinePaths(modules, files);
    expect(modCachePath).toBe("/go/pkg/mod/cache/");
    expect(vendorPath).toBe("");
  });
  it("finds no path with trimmed files", () => {
    const modules = [
      new GoModule("github.com/dep/a", "v0.0.1"),
      new GoModule("github.com/dep/b", "v0.1.0"),
    ];
    const files = [
      "github.com/my/project/main.go",
      "github.com/my/project/pkg/pkg.go",
      "github.com/dep/b@v0.1.0/pkg/b.go",
      "github.com/dep/a@v0.0.1/a.go",
      "fmt/fmt.go",
      "net/net.go",
      "vendor/golang.org/x/net/net.go",
    ];

    const { modCachePath, vendorPath } = determinePaths(modules, files);
    expect(modCachePath).toBe("");
    expect(vendorPath).toBe("");
  });
});
