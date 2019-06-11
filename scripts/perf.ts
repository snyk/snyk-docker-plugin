// usage: npm run perf -- [-ch] [image-name ...]

import { join } from "path";
import { Docker } from "../lib/docker";
import { execute } from "../lib/sub-process";

const IMAGE_NAMES = [
  "centos:7.6.1810",
  "nginx:1.13.10",
  "ubuntu:10.04",
  "alpine:3.9.4",
  "node:11.15-slim",
  "imiell/bad-dockerfile:latest",
  "node:10.11.0",
  "node:10.12.0",
  "python:2.7.15-stretch",
  // FAKE, should be named "fake-<size>g"
  "fake-1g",
  "fake-4g",
  "fake-15g",
];

const TXT_PATHS = [
  "lib/apk/db/installed",
  "var/lib/dpkg/status",
  "var/lib/apt/extended_states",
];

const MD5_PATHS = ["bin/ls"];

const HEADER_IMAGENAME = "IMAGE";
const HEADER_IMAGESIZE = "SIZE";
const HEADER_SAVE_TIME = "SAVE";
const HEADER_STATIC_TIME = "STATIC";
const HEADER_RUNTIME_TIME = "RUNTIME";
const HEADER_EXTRACTED = "EXTRACTED";

const HEADERS = [
  HEADER_IMAGENAME,
  HEADER_IMAGESIZE,
  HEADER_SAVE_TIME,
  HEADER_STATIC_TIME,
  HEADER_RUNTIME_TIME,
  HEADER_EXTRACTED,
];

let padding: number = 20;

async function test(
  imageNames: string[] = IMAGE_NAMES,
): Promise<Array<{ [key: string]: string }>> {
  const records: Array<{ [key: string]: string }> = [];

  // max image name length rounded to the nearest tenth
  padding = Math.ceil(Math.max(...imageNames.map((t) => t.length)) / 10) * 10;

  for (const imageName of imageNames) {
    const record: { [key: string]: string } = {};

    const id = await validate(imageName);
    if (!id) {
      continue;
    }

    record[HEADER_IMAGENAME] = imageName;
    record[HEADER_IMAGESIZE] = (await execute("docker", [
      "image",
      "inspect",
      imageName,
      "--format",
      "'{{.Size}}'",
    ])).stdout.trim();
    const docker = new Docker(imageName);

    let hrstart = process.hrtime();
    const result = await docker.save(async (err, imageTarPath) => {
      if (err) {
        throw err;
      }
      record[HEADER_SAVE_TIME] = hrdiff(hrstart).toString();
      return docker.analyze(imageTarPath, TXT_PATHS, MD5_PATHS);
    });

    record[HEADER_STATIC_TIME] = hrdiff(hrstart).toString();
    record[HEADER_EXTRACTED] = Object.keys(result.txt).length.toString();

    let tRuntime = 0;
    for (const txtPath of Object.keys(result.txt)) {
      hrstart = process.hrtime();
      const catFile = (await docker.catSafe(`${txtPath}`)).stdout;
      tRuntime += hrdiff(hrstart);
      if (result.txt[txtPath] !== catFile) {
        // tslint:disable-next-line:no-console
        console.error(`Error: Content not the same ${txtPath}`);
      }
    }
    record[HEADER_RUNTIME_TIME] = tRuntime.toString();

    records.push(record);
  }
  return records;
}

async function validate(imageName: string): Promise<string | null> {
  try {
    return (await execute("docker", [
      "image",
      "inspect",
      imageName,
      "--format",
      "'{{.Id}}'",
    ])).stdout.trim();
  } catch {
    // Ignore 1st failure, maybe the image does no exists locally
  }

  if (
    imageName.startsWith("fake-") &&
    imageName.endsWith("g") &&
    imageName.length > 6
  ) {
    // attempt to create the missing fake image of ?G size
    try {
      await execute(join(__dirname, "fake-image.sh"), [
        imageName.substr(5, imageName.length - 6),
      ]);
    } catch (err) {
      // Ignore fake image creation failure, make a 2nd attempt to inspect
    }
  } else {
    // attempt to pull the missing image
    try {
      await execute("docker", ["pull", imageName]);
    } catch {
      // Ignore pull failure, make a 2nd attempt to inspect
    }
  }

  try {
    return (await execute("docker", [
      "image",
      "inspect",
      imageName,
      "--format",
      "'{{.Id}}'",
    ])).stdout.trim();
  } catch (err) {
    // null image
  }
  // tslint:disable-next-line:no-console
  console.error(`Error: Failed to validate ${imageName}`);
  return null;
}

function hrdiff(hrtime: [number, number]): number {
  const hrdiff = process.hrtime(hrtime);
  return Math.round((hrdiff[0] * 1e9 + hrdiff[1]) / 1e6 + 1e-7) / 1e3;
}

function format(csv: boolean, record?: { [key: string]: string }): string {
  return HEADERS.map((v, i) => {
    return (record ? record[v] : v).toString().padEnd(csv ? 0 : padding);
  }).join(csv ? "," : "");
}

/**
 * command line argument parsing
 * @returns dict of opt and pos representing option arguments as a dict
 *  and positional as an array respectivly
 */
function argparse(): {
  opt: { [key: string]: string | boolean };
  pos: string[];
} {
  let index: number = 0;
  // look for the beginning of the arguments
  while (index < process.argv.length && process.argv[index] !== __filename) {
    index++;
  }
  index++;
  // options arguments
  const optargs: { [key: string]: string | boolean } = {};
  while (index < process.argv.length && process.argv[index].startsWith("-")) {
    const av: string = process.argv[index++];
    // end of options
    if (av === "--") {
      break;
    }
    // string value option
    if (av.startsWith("--") && index < process.argv.length) {
      index++;
      optargs[av.substr(2)] = process.argv[index++];
    }
    // boolean value option
    else {
      optargs[av.substr(1)] = true;
    }
  }
  // positional arguments
  const posargs: string[] = [];
  while (index < process.argv.length) {
    posargs.push(process.argv[index++]);
  }
  return { opt: optargs, pos: posargs };
}

function main() {
  const args = argparse();
  if ("h" in args.opt) {
    // tslint:disable-next-line:no-console
    console.log("usage: npm run perf -- [-ch] [image-name ...]");
    return;
  }
  const csv = "c" in args.opt;
  test(args.pos)
    .then((records: Array<{ [key: string]: string }>) => {
      // tslint:disable-next-line:no-console
      console.log(format(csv));
      for (const record of records) {
        // tslint:disable-next-line:no-console
        console.log(format(csv, record));
      }
    })
    .catch((reason) => {
      // tslint:disable-next-line:no-console
      console.error(reason);
    });
}

main();
