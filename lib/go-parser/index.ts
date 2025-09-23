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

function filePathMatches(filePath: string): boolean {
  const normalizedPath = path.normalize(filePath);
  const dirName = path.dirname(normalizedPath);
  return (
    !path.parse(normalizedPath).ext &&
    !ignoredPaths.some((ignorePath) => dirName.startsWith(ignorePath))
  );
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
      try {
        // Discard
        if (!buffer || bytesWritten === 0) {
          return resolve(undefined);
        }

        const binaryFile = elf.parse(buffer);

        const goBuildInfo = binaryFile.body.sections.find(
          (section) => section.name === ".go.buildinfo",
        );
        // Could be found in file headers
        const goBuildId = binaryFile.body.sections.find(
          (section) => section.name === ".note.go.buildid",
        );

        if (!goBuildInfo && !goBuildId) {
          return resolve(undefined);
        } else if (goBuildInfo) {
          const info = goBuildInfo.data
            .slice(0, buildInfoMagic.length)
            .toString(encoding);

          if (info === buildInfoMagic) {
            // to make sure we got a Go binary with module support, we try
            // reading it. Will throw an error if not.
            readRawBuildInfo(binaryFile);
            return resolve(binaryFile);
          }

          return resolve(undefined);
        } else if (goBuildId) {
          const strings = goBuildId.data
            .toString()
            .split(/\0+/g)
            .filter(Boolean);
          const go = strings[strings.length - 2];
          const buildIdParts = strings[strings.length - 1].split(path.sep);

          // Build ID's precise form is actionID/[.../]contentID.
          // Usually the buildID is simply actionID/contentID, but with exceptions.
          // https://github.com/golang/go/blob/master/src/cmd/go/internal/work/buildid.go#L23
          if (go === buildIdMagic && buildIdParts.length >= 2) {
            // to make sure we got a Go binary with module support, we try
            // reading it. Will throw an error if not.
            readRawBuildInfo(binaryFile);
            return resolve(binaryFile);
          }

          return resolve(undefined);
        }
      } catch (error) {
        // catching exception during elf file parse shouldn't fail the archive iteration
        // it either we recognize file as binary or not
        return resolve(undefined);
      }
    });

    stream.on("error", (error) => {
      reject(error);
    });

    stream.once("data", (chunk) => {
      const first4Bytes = chunk.toString(encoding, 0, 4);

      if (first4Bytes === elfHeaderMagic) {
        // Now that we know it's an ELF file, allocate the buffer
        buffer = Buffer.alloc(streamSize ?? elfBuildInfoSize);

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
  const scanResults: AppDepsScanResultWithoutTarget[] = [];

  for (const [filePath, goBinary] of Object.entries(filePathToContent)) {
    if (eventLoopSpinner.isStarving()) {
      await eventLoopSpinner.spin();
    }

    try {
      const depGraph = await new GoBinary(goBinary).depGraph();
      if (!depGraph) {
        continue;
      }

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
    } catch (err) {
      debug(`Go binary scan for file ${filePath} failed: ${err.message}`);
    }
  }

  return scanResults;
}
