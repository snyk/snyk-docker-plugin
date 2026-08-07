import * as path from "path";
import {
  extractImageContent,
  getContentAsBuffer,
  getContentAsString,
  isWhitedOutFile,
  symlinksWithLatestModifications,
} from "../../../lib/extractor";
import { extractArchive } from "../../../lib/extractor/docker-archive";
import { InvalidArchiveError } from "../../../lib/extractor/generic-archive-extractor";
import {
  ExtractAction,
  ExtractedLayers,
  SymlinkMap,
} from "../../../lib/extractor/types";
import { ImageType } from "../../../lib/types";
import { getFixture } from "../../util/index";

function baselineIsWhitedOutFile(filename: string) {
  return filename.match(/.wh./gm);
}

function baselineIsFileInFolder(file: string, folder: string): boolean {
  const folderPath = path.normalize(folder);
  const filePath = path.normalize(file);

  return filePath.startsWith(path.join(folderPath, path.sep));
}

function baselineIsFileInARemovedFolder(
  filename: string,
  removedFilesToIgnore: Set<string>,
): boolean {
  return Array.from(removedFilesToIgnore).some((removedFile) =>
    baselineIsFileInFolder(filename, removedFile),
  );
}

function baselineLayersWithLatestFileModifications(
  layers: ExtractedLayers[],
): ExtractedLayers {
  const extractedLayers: ExtractedLayers = {};
  const removedFilesToIgnore: Set<string> = new Set();

  for (const layer of layers) {
    for (const filename of Object.keys(layer)) {
      if (baselineIsWhitedOutFile(filename)) {
        removedFilesToIgnore.add(filename.replace(/.wh./, ""));
        continue;
      }
      if (removedFilesToIgnore.has(filename)) {
        continue;
      }
      if (baselineIsFileInARemovedFolder(filename, removedFilesToIgnore)) {
        continue;
      }
      if (!Reflect.has(extractedLayers, filename)) {
        extractedLayers[filename] = layer[filename];
      }
    }
  }
  return extractedLayers;
}

function optimizedWhiteoutToRemovedPath(filename: string): string {
  return path.normalize(filename.replace(/.wh./, ""));
}

function optimizedIsPathUnderAnyRemovedPath(
  candidatePath: string,
  removedPaths: Set<string>,
): boolean {
  let current = path.normalize(candidatePath);
  while (true) {
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    if (removedPaths.has(parent)) {
      return true;
    }
    current = parent;
  }
  return false;
}

function optimizedLayersWithLatestFileModifications(
  layers: ExtractedLayers[],
): ExtractedLayers {
  const extractedLayers: ExtractedLayers = {};
  const removedFilesToIgnore: Set<string> = new Set();

  for (const layer of layers) {
    for (const filename of Object.keys(layer)) {
      if (isWhitedOutFile(filename)) {
        removedFilesToIgnore.add(optimizedWhiteoutToRemovedPath(filename));
        continue;
      }
      if (removedFilesToIgnore.has(filename)) {
        continue;
      }
      if (optimizedIsPathUnderAnyRemovedPath(filename, removedFilesToIgnore)) {
        continue;
      }
      if (!Reflect.has(extractedLayers, filename)) {
        extractedLayers[filename] = layer[filename];
      }
    }
  }
  return extractedLayers;
}

const matchEverythingAction: ExtractAction = {
  actionName: "record",
  filePathMatches: () => true,
  callback: async (stream) => {
    stream.resume();
    return Buffer.from("x");
  },
};

async function extractUnmergedArchive(fixturePath: string) {
  const fixture = getFixture(fixturePath);
  try {
    return await extractArchive(fixture, [matchEverythingAction], {});
  } catch (error) {
    if (error instanceof InvalidArchiveError) {
      const { extractArchive: extractOciArchive } = await import(
        "../../../lib/extractor/oci-archive"
      );
      return extractOciArchive(fixture, [matchEverythingAction], {});
    }
    throw error;
  }
}

function bestOfRuns(fn: () => void, runs: number): number {
  const times: number[] = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    fn();
    times.push(performance.now() - start);
  }
  return Math.min(...times);
}

describe("merge hot path performance", () => {
  describe("getContentAsString and getContentAsBuffer", () => {
    const actionName = "test-action";
    const extractAction: ExtractAction = {
      actionName,
      filePathMatches: (filePath) => filePath.endsWith("/target"),
    };

    it("returns undefined when there is no match", () => {
      const extractedLayers: ExtractedLayers = {
        "/other/file": { [actionName]: "content" },
      };
      expect(
        getContentAsString(extractedLayers, extractAction),
      ).toBeUndefined();
      expect(
        getContentAsBuffer(extractedLayers, extractAction),
      ).toBeUndefined();
    });

    it("skips entries with matching actionName but failing filePathMatches", () => {
      const extractedLayers: ExtractedLayers = {
        "/wrong/path": { [actionName]: "wrong" },
        "/also/wrong": { [actionName]: "also wrong" },
      };
      expect(
        getContentAsString(extractedLayers, extractAction),
      ).toBeUndefined();
    });

    it("returns the first key in Object.keys order when several candidates match", () => {
      const extractedLayers: ExtractedLayers = {
        "/z/target": { [actionName]: "z" },
        "/a/target": { [actionName]: "a" },
        "/m/target": { [actionName]: "m" },
      };
      const expectedKey = Object.keys(extractedLayers).find((name) =>
        extractAction.filePathMatches(name),
      );
      expect(getContentAsString(extractedLayers, extractAction)).toEqual(
        extractedLayers[expectedKey!][actionName],
      );
    });

    it("returns string content via getContentAsString", () => {
      const extractedLayers: ExtractedLayers = {
        "/path/target": { [actionName]: "hello" },
      };
      expect(getContentAsString(extractedLayers, extractAction)).toEqual(
        "hello",
      );
      expect(
        getContentAsBuffer(extractedLayers, extractAction),
      ).toBeUndefined();
    });

    it("returns buffer content via getContentAsBuffer", () => {
      const buffer = Buffer.from("binary");
      const extractedLayers: ExtractedLayers = {
        "/path/target": { [actionName]: buffer },
      };
      expect(getContentAsBuffer(extractedLayers, extractAction)).toEqual(
        buffer,
      );
      expect(
        getContentAsString(extractedLayers, extractAction),
      ).toBeUndefined();
    });
  });

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
      const symlinkLayers: SymlinkMap[] = [
        { "/bin": "usr/bin" },
        {},
        { "/bin": "usr/old/bin" },
      ];
      const fileLayers: ExtractedLayers[] = [{}, { "/.wh.bin": {} }, {}];
      expect(
        symlinksWithLatestModifications(symlinkLayers, fileLayers),
      ).toEqual({
        "/bin": "usr/bin",
      });
    });

    it("keeps a symlink created in the same layer that whiteouts the path", () => {
      const symlinkLayers: SymlinkMap[] = [
        { "/bin": "usr/bin" },
        { "/bin": "old/bin" },
      ];
      const fileLayers: ExtractedLayers[] = [{ "/.wh.bin": {} }, {}];
      expect(
        symlinksWithLatestModifications(symlinkLayers, fileLayers),
      ).toEqual({
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

    it("removes a symlink nested several levels under a whited-out folder", () => {
      const symlinkLayers: SymlinkMap[] = [
        {},
        { "/opt/app/releases/current/bin": "releases/1/bin" },
      ];
      const fileLayers: ExtractedLayers[] = [{ "/.wh.opt": {} }, {}];
      expect(
        symlinksWithLatestModifications(symlinkLayers, fileLayers),
      ).toBeUndefined();
    });

    it("keeps a symlink whose path merely shares a prefix with a removed path", () => {
      const symlinkLayers: SymlinkMap[] = [{}, { "/opt/apple": "fruit/apple" }];
      const fileLayers: ExtractedLayers[] = [{ "/.wh.opt/app": {} }, {}];
      expect(
        symlinksWithLatestModifications(symlinkLayers, fileLayers),
      ).toEqual({
        "/opt/apple": "fruit/apple",
      });
    });
  });

  describe("file merge equivalence via extractImageContent", () => {
    const fixtures = [
      "docker-archives/docker-save/deleted-folder.tar",
      "docker-archives/docker-save/test-deleted.tar",
      "docker-archives/docker-save/two-adds-one-file-rm.tar",
    ];

    it.each(fixtures)(
      "merged keys match baseline for %s",
      async (fixturePath) => {
        const archiveContent = await extractUnmergedArchive(fixturePath);
        const baselineKeys = Object.keys(
          baselineLayersWithLatestFileModifications(archiveContent.layers),
        ).sort();
        const shipped = await extractImageContent(
          ImageType.DockerArchive,
          getFixture(fixturePath),
          [matchEverythingAction],
          {},
        );
        const shippedKeys = Object.keys(shipped.extractedLayers).sort();
        expect(shippedKeys).toEqual(baselineKeys);
      },
    );
  });

  describe("timing benchmarks", () => {
    let corpusPaths: string[] = [];
    let mergeLayerSets: ExtractedLayers[][] = [];

    beforeAll(async () => {
      const fixturePaths = [
        "docker-archives/docker-save/nginx.tar",
        "docker-archives/docker-save/deleted-folder.tar",
        "docker-archives/docker-save/test-deleted.tar",
        "docker-archives/docker-save/two-adds-one-file-rm.tar",
      ];
      corpusPaths = [];
      mergeLayerSets = [];
      for (const fixturePath of fixturePaths) {
        const content = await extractUnmergedArchive(fixturePath);
        mergeLayerSets.push(content.layers);
        for (const layer of content.layers) {
          corpusPaths.push(...Object.keys(layer));
        }
      }
    });

    it("optimized isWhitedOutFile is faster than baseline on harvested corpus", () => {
      const timingCorpus: string[] = [];
      for (const p of corpusPaths) {
        timingCorpus.push(p);
        const baseName = path.basename(p);
        timingCorpus.push(path.join(path.dirname(p), `.wh.${baseName}`));
      }

      baselineIsWhitedOutFile(timingCorpus[0]);
      isWhitedOutFile(timingCorpus[0]);

      const repetitions = 200;
      const baselineMs = bestOfRuns(() => {
        for (let rep = 0; rep < repetitions; rep++) {
          for (const p of timingCorpus) {
            baselineIsWhitedOutFile(p);
          }
        }
      }, 5);
      const optimizedMs = bestOfRuns(() => {
        for (let rep = 0; rep < repetitions; rep++) {
          for (const p of timingCorpus) {
            isWhitedOutFile(p);
          }
        }
      }, 5);

       
      console.log(
        `isWhitedOutFile timing: baseline=${baselineMs.toFixed(
          3,
        )}ms optimized=${optimizedMs.toFixed(3)}ms (corpus=${
          timingCorpus.length
        } paths)`,
      );
      expect(optimizedMs).toBeLessThan(baselineMs);
    });

    it("optimized file merge is faster than baseline on harvested corpus", async () => {
      baselineLayersWithLatestFileModifications(mergeLayerSets[0]);
      optimizedLayersWithLatestFileModifications(mergeLayerSets[0]);
      await extractImageContent(
        ImageType.DockerArchive,
        getFixture("docker-archives/docker-save/nginx.tar"),
        [matchEverythingAction],
        {},
      );

      const runAllMerges = (
        mergeFn: (layers: ExtractedLayers[]) => ExtractedLayers,
      ) => {
        for (const layers of mergeLayerSets) {
          mergeFn(layers);
        }
      };

      const baselineMs = bestOfRuns(() => {
        runAllMerges(baselineLayersWithLatestFileModifications);
      }, 5);
      const optimizedMs = bestOfRuns(() => {
        runAllMerges(optimizedLayersWithLatestFileModifications);
      }, 5);

       
      console.log(
        `file merge timing: baseline=${baselineMs.toFixed(
          3,
        )}ms optimized=${optimizedMs.toFixed(3)}ms (${
          mergeLayerSets.length
        } layer sets)`,
      );
      expect(optimizedMs).toBeLessThan(baselineMs);
    });
  });

  it("logs full extractImageContent timing for nginx.tar", async () => {
    const start = performance.now();
    await extractImageContent(
      ImageType.DockerArchive,
      getFixture("docker-archives/docker-save/nginx.tar"),
      [matchEverythingAction],
      {},
    );
    const elapsedMs = performance.now() - start;
     
    console.log(
      `extractImageContent(nginx.tar) elapsed=${elapsedMs.toFixed(3)}ms`,
    );
  });
});
