import * as Debug from "debug";
import * as elf from "elfy";
import { eventLoopSpinner } from "event-loop-spinner";
// NOTE: Paths will always be normalized to POSIX even on Windows.
// This makes it easier to ignore differences between Linux and Windows.
import { posix as path } from "path";
import { Readable } from "stream";

import {
  AppDepsScanResultWithoutTarget,
  FilePathToElfContent,
} from "../analyzer/applications/types";
import { ExtractAction } from "../extractor/types";
import { DepGraphFact } from "../facts";
import { GoBinary, readRawBuildInfo } from "./go-binary";

const debug = Debug("snyk");

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

export const DEP_GRAPH_TYPE = "gomodules";

export function filePathMatches(filePath: string): boolean {
  const normalizedPath = path.normalize(filePath);
  const dirName = path.dirname(normalizedPath);
  const posixPath = filePath.replace(/\\/g, '/');
  const hasExtension = !!path.posix.parse(posixPath).ext;
  const isInIgnoredPath = ignoredPaths.some((ignorePath) =>
    dirName.startsWith(ignorePath),
  );
  const matches = !hasExtension && !isInIgnoredPath;

  // Log file path checking details for debugging
  console.log(
    `🔍 filePathMatches: "${filePath}" -> normalized: "${normalizedPath}"`,
  );
  console.log(
    `🔍   hasExtension: ${hasExtension}, isInIgnoredPath: ${isInIgnoredPath}, matches: ${matches}`,
  );
  if (isInIgnoredPath) {
    console.log(
      `🔍   Ignored because dirName "${dirName}" matches ignored paths`,
    );
  }

  return matches;
}

export const getGoModulesContentAction: ExtractAction = {
  actionName: "gomodules",
  filePathMatches,
  callback: findGoBinaries,
};

async function findGoBinaries(
  stream: Readable,
  streamSize?: number,
): Promise<any> {
  console.log(
    `🔍 findGoBinaries - Starting binary analysis, streamSize: ${streamSize}`,
  );

  return new Promise((resolve, reject) => {
    const encoding = "binary";
    const buildIdMagic = "Go";
    const elfHeaderMagic = "\x7FELF";
    const buildInfoMagic = "\xff Go buildinf:";
    // ELF section headers and so ".go.buildinfo" & ".note.go.buildid" blobs are available in the first 64kb
    const elfBuildInfoSize = 64 * 1024;

    let buffer: Buffer | null = null;
    let bytesWritten = 0;

    stream.on("end", () => {
      console.log(
        `🔍 findGoBinaries - Stream ended, bytesWritten: ${bytesWritten}, hasBuffer: ${!!buffer}`,
      );

      try {
        // Discard
        if (!buffer || bytesWritten === 0) {
          console.log(
            `🔍 findGoBinaries - ❌ No buffer or no bytes written, discarding`,
          );
          return resolve(undefined);
        }

        console.log(`🔍 findGoBinaries - Parsing ELF file...`);
        const binaryFile = elf.parse(buffer);

        const goBuildInfo = binaryFile.body.sections.find(
          (section) => section.name === ".go.buildinfo",
        );
        // Could be found in file headers
        const goBuildId = binaryFile.body.sections.find(
          (section) => section.name === ".note.go.buildid",
        );

        console.log(
          `🔍 findGoBinaries - Found sections: goBuildInfo=${!!goBuildInfo}, goBuildId=${!!goBuildId}`,
        );

        if (!goBuildInfo && !goBuildId) {
          console.log(
            `🔍 findGoBinaries - ❌ No Go build info or build ID sections found`,
          );
          return resolve(undefined);
        } else if (goBuildInfo) {
          const info = goBuildInfo.data
            .slice(0, buildInfoMagic.length)
            .toString(encoding);

          console.log(
            `🔍 findGoBinaries - Checking goBuildInfo magic: "${info}" === "${buildInfoMagic}"`,
          );

          if (info === buildInfoMagic) {
            console.log(
              `🔍 findGoBinaries - ✅ Go build info magic matched, reading raw build info...`,
            );
            // to make sure we got a Go binary with module support, we try
            // reading it. Will throw an error if not.
            readRawBuildInfo(binaryFile);
            console.log(
              `🔍 findGoBinaries - ✅ Successfully validated Go binary`,
            );
            return resolve(binaryFile);
          }

          console.log(
            `🔍 findGoBinaries - ❌ Go build info magic did not match`,
          );
          return resolve(undefined);
        } else if (goBuildId) {
          console.log(`🔍 findGoBinaries - Checking goBuildId...`);
          const strings = goBuildId.data
            .toString()
            .split(/\0+/g)
            .filter(Boolean);
          const go = strings[strings.length - 2];
          const buildIdParts = strings[strings.length - 1].split(path.sep);

          console.log(
            `🔍 findGoBinaries - BuildId check: go="${go}", buildIdParts.length=${buildIdParts.length}, magic="${buildIdMagic}"`,
          );

          // Build ID's precise form is actionID/[.../]contentID.
          // Usually the buildID is simply actionID/contentID, but with exceptions.
          // https://github.com/golang/go/blob/master/src/cmd/go/internal/work/buildid.go#L23
          if (go === buildIdMagic && buildIdParts.length >= 2) {
            console.log(
              `🔍 findGoBinaries - ✅ Go build ID matched, reading raw build info...`,
            );
            // to make sure we got a Go binary with module support, we try
            // reading it. Will throw an error if not.
            readRawBuildInfo(binaryFile);
            console.log(
              `🔍 findGoBinaries - ✅ Successfully validated Go binary via build ID`,
            );
            return resolve(binaryFile);
          }

          console.log(
            `🔍 findGoBinaries - ❌ Go build ID did not match criteria`,
          );
          return resolve(undefined);
        }
      } catch (error) {
        console.log(
          `🔍 findGoBinaries - ❌ Exception during ELF parsing: ${error.message}`,
        );
        // catching exception during elf file parse shouldn't fail the archive iteration
        // it either we recognize file as binary or not
        return resolve(undefined);
      }
    });

    stream.on("error", (error) => {
      console.log(`🔍 findGoBinaries - ❌ Stream error: ${error.message}`);
      reject(error);
    });

    stream.once("data", (chunk) => {
      const first4Bytes = chunk.toString(encoding, 0, 4);
      console.log(
        `🔍 findGoBinaries - First 4 bytes: "${first4Bytes}" (expected ELF: "${elfHeaderMagic}")`,
      );

      if (first4Bytes === elfHeaderMagic) {
        console.log(
          `🔍 findGoBinaries - ✅ ELF header detected, allocating buffer...`,
        );
        // Now that we know it's an ELF file, allocate the buffer
        // If the streamSize is larger than node.js's max buffer length
        // we should cap the size at that value. The liklihood
        // of a node module being this size is near zero, so we should
        // be okay doing this
        const bufferSize = Math.min(
          streamSize ?? elfBuildInfoSize,
          require("buffer").constants.MAX_LENGTH,
        );
        buffer = Buffer.alloc(bufferSize);
        console.log(
          `🔍 findGoBinaries - Allocated buffer of size: ${bufferSize}`,
        );

        bytesWritten += Buffer.from(chunk).copy(buffer, bytesWritten, 0);

        // Listen to next chunks only if it's an ELF executable
        stream.addListener("data", (chunk) => {
          if (buffer && bytesWritten < buffer.length) {
            // Make sure we don't exceed the buffer capacity. Don't copy more
            // than the buffer can handle, and don't exceed the chunk length
            const bytesToWrite = Math.min(
              buffer.length - bytesWritten,
              chunk.length,
            );
            bytesWritten += Buffer.from(chunk).copy(
              buffer,
              bytesWritten,
              0,
              bytesToWrite,
            );
          }
        });
      } else {
        console.log(`🔍 findGoBinaries - ❌ Not an ELF file, exiting early`);
        // Not an ELF file, exit early without allocating memory
        return resolve(undefined);
      }
    });
  });
}

/**
 * Build depGraphs for each Go executable
 * @param filePathToContent
 */
export async function goModulesToScannedProjects(
  filePathToContent: FilePathToElfContent,
): Promise<AppDepsScanResultWithoutTarget[]> {
  console.log("🔍 goModulesToScannedProjects - Starting with file paths:");
  console.log(
    "🔍 Input filePathToContent keys:",
    Object.keys(filePathToContent),
  );
  console.log("🔍 Platform info:", {
    platform: process.platform,
    pathSep: path.sep,
    posixSep: path.posix.sep,
  });

  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, goBinary] of Object.entries(filePathToContent)) {
    console.log(`🔍 Processing Go binary at path: "${filePath}"`);
    console.log(
      `🔍 Binary object type: ${typeof goBinary}, has body: ${!!goBinary?.body}`,
    );

    if (eventLoopSpinner.isStarving()) {
      await eventLoopSpinner.spin();
    }

    try {
      console.log(`🔍 Creating GoBinary instance for: ${filePath}`);
      const depGraph = await new GoBinary(goBinary).depGraph();
      if (!depGraph) {
        console.log(`🔍 ❌ No depGraph generated for: ${filePath}`);
        continue;
      }

      console.log(`🔍 ✅ Successfully created depGraph for: ${filePath}`);
      console.log(
        `🔍 DepGraph info - name: ${depGraph.rootPkg.name}, deps count: ${
          depGraph.getDepPkgs().length
        }`,
      );

      const depGraphFact: DepGraphFact = {
        type: "depGraph",
        data: depGraph,
      };
      scanResults.push({
        facts: [depGraphFact],
        identity: {
          type: DEP_GRAPH_TYPE,
          // TODO: The path will contain forward slashes on Linux or backslashes on Windows.
          // So if you scanned the exact same image but from two different machines,
          // we'd generate two different identities.
          // These two identities would create two different Projects if monitored... so is this a bug?
          // If we enforce forward-slashes in every case, would that create duplicate Projects
          // for existing users who are using the current "backslashes on Windows" behaviour?
          targetFile: filePath,
        },
      });
      console.log(`🔍 ✅ Added scan result for: ${filePath}`);
    } catch (err) {
      console.log(
        `🔍 ❌ Go binary scan for file ${filePath} failed: ${err.message}`,
      );
      debug(`Go binary scan for file ${filePath} failed: ${err.message}`);
    }
  }

  console.log(
    `🔍 goModulesToScannedProjects - Completed. Total scan results: ${scanResults.length}`,
  );
  console.log(
    "🔍 Final scan results paths:",
    scanResults.map((r) => r.identity.targetFile),
  );
  return scanResults;
}
