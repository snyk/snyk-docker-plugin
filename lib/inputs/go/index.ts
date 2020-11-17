import * as elf from "elfy";
import * as path from "path";
import { Readable } from "stream";
import { ExtractAction } from "../../extractor/types";

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

function filePathMatches(filePath: string): boolean {
  const dirName = path.dirname(filePath);
  return (
    !path.parse(filePath).ext &&
    !ignoredPaths.some((ignorePath) => dirName.startsWith(ignorePath))
  );
}

export const getGoModulesContentAction: ExtractAction = {
  actionName: "gomodules",
  filePathMatches,
  callback: findGoBinaries,
};

async function findGoBinaries(stream: Readable): Promise<any> {
  return new Promise((resolve, reject) => {
    const encoding = "binary";
    const buildIdMagic = "Go";
    const elfHeaderMagic = "\x7FELF";
    const buildInfoMagic = "\xff Go buildinf:";

    const result: Buffer[] = [];

    stream.on("end", () => {
      // Discard
      if (result.length === 0) {
        return resolve();
      }

      const buffer = Buffer.concat(result);
      const binaryFile = elf.parse(buffer);
      const goBuildInfo = binaryFile.body.sections.find(
        (section) => section.name === ".go.buildinfo",
      );
      // Could be found in file headers
      const goBuildId = binaryFile.body.sections.find(
        (section) => section.name === ".note.go.buildid",
      );

      if (!goBuildInfo && !goBuildId) {
        return resolve();
      } else if (goBuildInfo) {
        const info = goBuildInfo.data
          .slice(0, buildInfoMagic.length)
          .toString(encoding);

        if (info === buildInfoMagic) {
          return resolve(binaryFile);
        }

        return resolve();
      } else if (goBuildId) {
        const strings = goBuildId.data
          .toString()
          .split(/\0+/g)
          .filter(Boolean);
        const go = strings[strings.length - 2];
        const buildIdParts = strings[strings.length - 1].split("/");

        // Build ID's precise form is actionID/[.../]contentID.
        // Usually the buildID is simply actionID/contentID, but with exceptions.
        // https://github.com/golang/go/blob/master/src/cmd/go/internal/work/buildid.go#L23
        if (go === buildIdMagic && buildIdParts.length >= 2) {
          return resolve(binaryFile);
        }

        return resolve();
      }
    });

    stream.on("error", (error) => reject(error));

    stream.once("data", (chunk) => {
      const first4Bytes = chunk.toString(encoding, 0, 4);

      if (first4Bytes === elfHeaderMagic) {
        result.push(Buffer.from(chunk));
        // Listen to next chunks only if it's an ELF executable
        stream.addListener("data", (chunk) => result.push(Buffer.from(chunk)));
      }
    });
  });
}
