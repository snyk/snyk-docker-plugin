import { eventLoopSpinner } from "event-loop-spinner";

export { DiscoveredDirectory, DiscoveredFile, parseLsOutput, iterateFiles };

interface DiscoveredDirectory {
  name: string;
  subDirs: DiscoveredDirectory[];
  files: DiscoveredFile[];
}

interface DiscoveredFile {
  name: string;
  path: string;
}

/**
 * Iterate over all files of a given DiscoveredDirectory structure.
 */
async function iterateFiles(
  root: DiscoveredDirectory,
  iterator: (f: DiscoveredFile) => void,
) {
  for (const f of root.files) {
    iterator(f);
  }

  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }

  for (const d of root.subDirs) {
    await iterateFiles(d, iterator);
  }
}

/**
 * Parse the output of a ls command and return a DiscoveredDirectory
 * structure. Can handle plain and recursive output. Root path will
 * always be normalized to '/'. State scope is a directory i.e. the
 * parser can handle missing parent directories or an out-of-order
 * directory sequence.
 */
function parseLsOutput(output: string): DiscoveredDirectory {
  const outputLines = output.trim().split("\n");
  const isRecursiveOutput = outputLines[0].endsWith(":");
  const res = {
    name: "/",
    subDirs: [] as DiscoveredDirectory[],
    files: [] as DiscoveredFile[],
  };

  let pathPrefix = "";
  let currPath = "/";
  let currDir = res;

  outputLines.forEach((i, n) => {
    if (i.endsWith(":")) {
      if (n === 0 && i !== "/:") {
        pathPrefix = i.substring(0, i.length - 1);
      }
      currPath = i.substring(pathPrefix.length, i.length - 1) || "/";
      if (currPath !== "/") {
        currDir = getSubDir(res, currPath.substring(1).split("/"));
      } else {
        currDir = res;
      }
    } else if (i !== "" && !i.endsWith("/") && i !== "." && i !== "..") {
      currDir.files.push({
        name: i,
        path: currPath,
      });
    } else if (
      !isRecursiveOutput &&
      i.endsWith("/") &&
      i !== "./" &&
      i !== "../"
    ) {
      currDir.subDirs.push({
        name: i.substring(0, i.length - 1),
        subDirs: [],
        files: [],
      });
    }
  });

  return res;
}

/**
 * Return a subdirectory of a given DiscoveredDirectory. Create
 * parent directories of the subdirectory if necessary.
 */
function getSubDir(
  root: DiscoveredDirectory,
  path: string[],
): DiscoveredDirectory {
  let subdir: DiscoveredDirectory | undefined;

  if (!path || !path.length) {
    return root;
  }

  subdir = root.subDirs.find((i) => i.name === path[0]);
  if (!subdir) {
    subdir = { name: path[0], subDirs: [], files: [] };
    root.subDirs.push(subdir);
  }

  return getSubDir(subdir, path.slice(1));
}
