import { minimatch, Minimatch } from "minimatch";
import { posix as path } from "path";

import { extractImageContent } from "../../lib/extractor";
import { ExtractAction } from "../../lib/extractor/types";
import { getGoModulesContentAction } from "../../lib/go-parser";
import { generateExtractAction } from "../../lib/inputs/file-pattern/static";
import { ImageType } from "../../lib/types";
import { getFixture } from "../util";

const nginxFixture = getFixture("docker-archives/docker-save/nginx.tar");

const matchOptions = {
  windowsPathsNoEscape: true,
  optimizationLevel: 0,
} as const;

const ignoredPaths = [
  path.normalize("/boot"),
  path.normalize("/dev"),
  path.normalize("/etc"),
  path.normalize("/home"),
  path.normalize("/media"),
  path.normalize("/mnt"),
  path.normalize("/proc"),
  path.normalize("/root"),
  path.normalize("/run"),
  path.normalize("/sbin"),
  path.normalize("/sys"),
  path.normalize("/tmp"),
  path.normalize("/var"),
];

function baselineGoFilePathMatches(filePath: string): boolean {
  const normalizedPath = path.normalize(filePath);
  const dirName = path.dirname(normalizedPath);
  const forwardSlashedPath = filePath.replace(/\\/g, "/");
  const hasExtension = !!path.parse(forwardSlashedPath).ext;
  const isInIgnoredPath = ignoredPaths.some((ignorePath) =>
    dirName.startsWith(ignorePath),
  );

  return !hasExtension && !isInIgnoredPath;
}

function baselineGeneratePathMatcher(
  globsInclude: string[],
  globsExclude: string[],
): (filePath: string) => boolean {
  return (filePath: string): boolean => {
    if (globsExclude.some((glob) => minimatch(filePath, glob, matchOptions))) {
      return false;
    }

    return globsInclude.some((glob) => minimatch(filePath, glob, matchOptions));
  };
}

const cheapCallback = async () => "stub";

const explicitGoPaths = [
  "C:\\Windows\\System32\\kubectl",
  "/app/foo.bar/baz",
  "/etc/passwd",
  "/var/log/app",
];

const explicitGlobPaths = [
  "/etc/nginx/nginx.conf",
  "/usr/share/nginx/html/index.html",
];

function bestOf(runs: number[], count: number): number {
  return [...runs]
    .sort((a, b) => a - b)
    .slice(0, count)
    .pop()!;
}

describe("file matching performance", () => {
  let corpusPaths: string[];

  beforeAll(async () => {
    const harvestAction: ExtractAction = {
      actionName: "harvest-paths",
      filePathMatches: () => true,
      callback: cheapCallback,
    };

    const harvested = await extractImageContent(
      ImageType.DockerArchive,
      nginxFixture,
      [harvestAction],
      {},
    );

    corpusPaths = [
      ...new Set([
        ...Object.keys(harvested.extractedLayers),
        ...explicitGoPaths,
        ...explicitGlobPaths,
      ]),
    ];
  });

  describe("Go filePathMatches equivalence", () => {
    const shippedGoFilePathMatches = getGoModulesContentAction.filePathMatches;

    it("matches the inlined baseline for every harvested corpus path", () => {
      for (const filePath of corpusPaths) {
        expect(shippedGoFilePathMatches(filePath)).toBe(
          baselineGoFilePathMatches(filePath),
        );
      }
    });

    it("covers explicit Windows, dotted extension-less, and ignored-path cases", () => {
      expect(shippedGoFilePathMatches("C:\\Windows\\System32\\kubectl")).toBe(
        baselineGoFilePathMatches("C:\\Windows\\System32\\kubectl"),
      );
      expect(shippedGoFilePathMatches("/app/foo.bar/baz")).toBe(
        baselineGoFilePathMatches("/app/foo.bar/baz"),
      );
      expect(shippedGoFilePathMatches("/etc/passwd")).toBe(false);
      expect(shippedGoFilePathMatches("/var/log/app")).toBe(false);
    });
  });

  describe("glob path matcher equivalence", () => {
    const shippedGlobMatcher = generateExtractAction(
      ["**/*.txt", "**/etc/**", "**/var/**"],
      ["**/mock.txt"],
    ).filePathMatches;
    const baselineGlobMatcher = baselineGeneratePathMatcher(
      ["**/*.txt", "**/etc/**", "**/var/**"],
      ["**/mock.txt"],
    );

    it("matches the inlined baseline for every harvested corpus path", () => {
      for (const filePath of corpusPaths) {
        expect(shippedGlobMatcher(filePath)).toBe(
          baselineGlobMatcher(filePath),
        );
      }
    });

    it("handles comment globs the same way as the baseline minimatch() form", () => {
      const commentGlob = "#ignore-me";
      const samplePath = "/etc/nginx/nginx.conf";
      const baselineResult = minimatch(samplePath, commentGlob, matchOptions);
      const compiledMatcher = new Minimatch(commentGlob, matchOptions);

      expect(compiledMatcher.match(samplePath)).toBe(baselineResult);
      expect(baselineGeneratePathMatcher([commentGlob], [])(samplePath)).toBe(
        baselineResult,
      );
      expect(
        generateExtractAction([commentGlob], []).filePathMatches(samplePath),
      ).toBe(baselineResult);
    });

    it("handles exclude patterns that shadow includes", () => {
      const matcher = generateExtractAction(
        ["**/**"],
        ["**/mock.txt"],
      ).filePathMatches;
      const baselineMatcher = baselineGeneratePathMatcher(
        ["**/**"],
        ["**/mock.txt"],
      );

      expect(matcher("/snyk/mock.txt")).toBe(false);
      expect(baselineMatcher("/snyk/mock.txt")).toBe(false);
      expect(matcher("/etc/os-release")).toBe(true);
      expect(baselineMatcher("/etc/os-release")).toBe(true);
    });

    it("matches a non-empty subset of harvested corpus paths", () => {
      const includeMatcher = generateExtractAction(
        ["**/*.txt"],
        [],
      ).filePathMatches;
      const matchedPaths = corpusPaths.filter((filePath) =>
        includeMatcher(filePath),
      );

      expect(matchedPaths.length).toBeGreaterThan(0);
      expect(matchedPaths).toContain("/snyk/mock.txt");
    });
  });

  describe("extractImageContent end-to-end equivalence and timing", () => {
    const e2eGlobsInclude = ["**/**"];
    const e2eGlobsExclude: string[] = [];

    function makeGlobAction(
      filePathMatches: (filePath: string) => boolean,
    ): ExtractAction {
      return {
        ...generateExtractAction(e2eGlobsInclude, e2eGlobsExclude),
        filePathMatches,
      };
    }

    const shippedGlobAction = makeGlobAction(
      generateExtractAction(e2eGlobsInclude, e2eGlobsExclude).filePathMatches,
    );
    const baselineGlobAction = makeGlobAction(
      baselineGeneratePathMatcher(e2eGlobsInclude, e2eGlobsExclude),
    );

    function makeGoAction(
      filePathMatches: (filePath: string) => boolean,
    ): ExtractAction {
      return {
        ...getGoModulesContentAction,
        filePathMatches,
        callback: cheapCallback,
      };
    }

    async function runExtraction(
      globAction: ExtractAction,
      goFilePathMatches: (filePath: string) => boolean,
    ): Promise<string[]> {
      const result = await extractImageContent(
        ImageType.DockerArchive,
        nginxFixture,
        [globAction, makeGoAction(goFilePathMatches)],
        {},
      );

      return Object.keys(result.extractedLayers).sort();
    }

    it("produces identical extracted layer keys for baseline and shipped predicates", async () => {
      const baselineKeys = await runExtraction(
        baselineGlobAction,
        baselineGoFilePathMatches,
      );
      const shippedKeys = await runExtraction(
        shippedGlobAction,
        getGoModulesContentAction.filePathMatches,
      );

      expect(shippedKeys).toEqual(baselineKeys);
    });

    it("runs faster with shipped predicates than with the baseline copy", async () => {
      const timedRuns = async (
        globAction: ExtractAction,
        goFilePathMatches: (filePath: string) => boolean,
      ): Promise<number[]> => {
        await runExtraction(globAction, goFilePathMatches);

        const runs: number[] = [];
        for (let i = 0; i < 3; i++) {
          const start = performance.now();
          await runExtraction(globAction, goFilePathMatches);
          runs.push(performance.now() - start);
        }
        return runs;
      };

      const baselineRuns = await timedRuns(
        baselineGlobAction,
        baselineGoFilePathMatches,
      );
      const shippedRuns = await timedRuns(
        shippedGlobAction,
        getGoModulesContentAction.filePathMatches,
      );

      const baselineBest = bestOf(baselineRuns, 1);
      const shippedBest = bestOf(shippedRuns, 1);

       
      console.log(
        `file matching e2e best-of-3 ms: baseline=${baselineBest.toFixed(
          3,
        )}, shipped=${shippedBest.toFixed(3)}`,
      );

      expect(shippedBest).toBeLessThan(baselineBest);
    });

    it("matches the baseline arm key set when using untouched shipped actions", async () => {
      const baselineKeys = await runExtraction(
        baselineGlobAction,
        baselineGoFilePathMatches,
      );

      const shippedResult = await extractImageContent(
        ImageType.DockerArchive,
        nginxFixture,
        [shippedGlobAction, getGoModulesContentAction],
        {},
      );

      expect(Object.keys(shippedResult.extractedLayers).sort()).toEqual(
        baselineKeys,
      );
    });
  });
});
