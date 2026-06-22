import { symlinksWithLatestModifications } from "../../../lib/extractor";
import { ExtractedLayers, SymlinkMap } from "../../../lib/extractor/types";

describe("symlinksWithLatestModifications", () => {
  it("uses the newest layer when the same path appears in multiple layers", () => {
    const symlinkLayers: SymlinkMap[] = [
      { "/bin": "usr/local/bin" },
      { "/bin": "usr/bin" },
    ];

    expect(symlinksWithLatestModifications(symlinkLayers, [{}, {}])).toEqual({
      "/bin": "usr/local/bin",
    });
  });

  it("merges symlinks from all layers when there is no conflict", () => {
    const symlinkLayers: SymlinkMap[] = [
      { "/bin": "usr/bin" },
      { "/lib": "usr/lib" },
      { "/etc": "usr/etc" },
    ];

    expect(
      symlinksWithLatestModifications(symlinkLayers, [{}, {}, {}]),
    ).toEqual({
      "/bin": "usr/bin",
      "/lib": "usr/lib",
      "/etc": "usr/etc",
    });
  });

  it("removes a symlink when a newer layer whiteouts the path", () => {
    const symlinkLayers: SymlinkMap[] = [{}, { "/bin": "usr/bin" }];
    const fileLayers: ExtractedLayers[] = [{ "/.wh.bin": {} }, {}];

    expect(
      symlinksWithLatestModifications(symlinkLayers, fileLayers),
    ).toBeUndefined();
  });

  it("does not re-add a whiteouted symlink from an older layer", () => {
    const symlinkLayers: SymlinkMap[] = [
      {},
      { "/bin": "usr/bin" },
      { "/bin": "usr/old/bin" },
    ];
    const fileLayers: ExtractedLayers[] = [{ "/.wh.bin": {} }, {}, {}];

    expect(
      symlinksWithLatestModifications(symlinkLayers, fileLayers),
    ).toBeUndefined();
  });

  it("keeps a symlink re-created in a newer layer after an older layer deleted it", () => {
    // Newest layer re-creates /bin after the middle layer deleted it; the
    // middle layer's whiteout must only hide the oldest layer's symlink.
    const symlinkLayers: SymlinkMap[] = [
      { "/bin": "usr/bin" },
      {},
      { "/bin": "usr/old/bin" },
    ];
    const fileLayers: ExtractedLayers[] = [{}, { "/.wh.bin": {} }, {}];

    expect(symlinksWithLatestModifications(symlinkLayers, fileLayers)).toEqual({
      "/bin": "usr/bin",
    });
  });

  it("keeps a symlink created in the same layer that whiteouts the path", () => {
    // usrmerge pattern: one layer deletes the /bin directory and creates the
    // /bin symlink; per the OCI spec a whiteout only hides lower layers.
    const symlinkLayers: SymlinkMap[] = [
      { "/bin": "usr/bin" },
      { "/bin": "old/bin" },
    ];
    const fileLayers: ExtractedLayers[] = [{ "/.wh.bin": {} }, {}];

    expect(symlinksWithLatestModifications(symlinkLayers, fileLayers)).toEqual({
      "/bin": "usr/bin",
    });
  });

  it("keeps a base-layer symlink untouched by newer layers", () => {
    const symlinkLayers: SymlinkMap[] = [{}, {}, { "/lib": "usr/lib" }];

    expect(
      symlinksWithLatestModifications(symlinkLayers, [{}, {}, {}]),
    ).toEqual({
      "/lib": "usr/lib",
    });
  });

  it("removes symlinks under a folder whited out by a newer layer", () => {
    const symlinkLayers: SymlinkMap[] = [
      {},
      { "/opt/app/current": "releases/1" },
    ];
    const fileLayers: ExtractedLayers[] = [{ "/.wh.opt": {} }, {}];

    expect(
      symlinksWithLatestModifications(symlinkLayers, fileLayers),
    ).toBeUndefined();
  });
});
