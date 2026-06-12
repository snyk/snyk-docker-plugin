import * as fs from "fs";
import * as path from "path";
import * as tar from "tar-stream";
import { extractImageLayer } from "../../../lib/extractor/layer";
import { ExtractAction } from "../../../lib/extractor/types";
import { getGoModulesContentAction } from "../../../lib/go-parser";
const getFixture = (fixturePath) =>
  path.join(__dirname, "../../fixtures", fixturePath);

describe("layer extractor: layer contain bad elf file", () => {
  it("it should return empty file object", () => {
    const staticAnalysisActions: ExtractAction[] = [];
    staticAnalysisActions.push(...[getGoModulesContentAction]);
    const stream = fs.createReadStream(
      getFixture("extracted-layers/layer_with_bad_elf_file.tar"),
    );
    const p = extractImageLayer(stream, staticAnalysisActions);
    expect(p).resolves.toMatchObject({ extractedLayers: {}, symlinks: {} });
  });
});

describe("layer extractor: layer contain cgo compiled go file", () => {
  it("it should return empty file object", () => {
    const staticAnalysisActions: ExtractAction[] = [];
    staticAnalysisActions.push(...[getGoModulesContentAction]);
    const stream = fs.createReadStream(
      getFixture("extracted-layers/cgo-compiled-file.tar"),
    );
    const p = extractImageLayer(stream, staticAnalysisActions);
    expect(p).resolves.toMatchObject({ extractedLayers: {}, symlinks: {} });
  });
});

describe("layer extractor: symlink capture", () => {
  it("records symlinks with absolute targets and ignores other entry types", async () => {
    const pack = tar.pack();
    // relative target resolves against the symlink's own directory
    pack.entry({
      name: "usr/bin/python3",
      type: "symlink",
      linkname: "python3.12",
    });
    // ".." segments in relative targets resolve too
    pack.entry({
      name: "usr/lib/libfoo.so",
      type: "symlink",
      linkname: "../share/foo/libfoo.so",
    });
    // absolute targets are stored normalized
    pack.entry({ name: "bin", type: "symlink", linkname: "/usr//bin" });
    // hard links are alternate names for the same inode, not redirects
    pack.entry({
      name: "usr/bin/[",
      type: "link",
      linkname: "usr/bin/busybox",
    });
    // regular files are not symlinks
    pack.entry({ name: "etc/hostname", type: "file" }, "myhost\n");
    pack.finalize();

    const { symlinks } = await extractImageLayer(pack, []);

    expect(symlinks).toEqual({
      [path.join(path.sep, "usr", "bin", "python3")]: "/usr/bin/python3.12",
      [path.join(path.sep, "usr", "lib", "libfoo.so")]:
        "/usr/share/foo/libfoo.so",
      [path.join(path.sep, "bin")]: "/usr/bin",
    });
  });
});
