#! /usr/bin/env ts-node

// tslint:disable:no-console

import { scan } from "../lib/scan";

process.on("uncaughtException", (err) => {
  console.log("UNCAUGHT EXCEPTION! %s", err);
  process.exit(1);
});

const DEFAULT_NUMBER_OF_RUNS = 10;

async function main() {
  try {
    validateArgs();

    const imageToScan = process.argv[2];
    const numberOfRuns = Number(process.argv[3]) || DEFAULT_NUMBER_OF_RUNS;
    console.log(`scanning ${imageToScan}`);
    const startTime = Date.now();

    for (let i = 0; i < numberOfRuns; i++) {
      console.log(`scan # ${i}`);
      await scan({
        "app-vulns": true,
        path: `docker-archive:${imageToScan}`,
      });
    }

    console.log(
      `average time per complete scan: ${(Date.now() - startTime) /
        numberOfRuns}`,
    );
  } catch (error) {
    console.log(error);
  }
}

function validateArgs() {
  if (process.argv.length < 3 || !process.argv[2].endsWith(".tar")) {
    throw new Error(
      `First argument must be a path to a saved image, .tar file`,
    );
  }

  if (!(process.argv[3] && !isNaN(Number(process.argv[3])))) {
    throw new Error(
      `Invalid argument '${process.argv[3]}' expected a number (number of runs).`,
    );
  }
}

main()
  .then(() => "Done!" && process.exit(0))
  .catch((err) => {
    console.log(err);
    process.exit(1);
  });
