#!/usr/bin/env ts-node

import * as commandLineArgs from "command-line-args";
import { scan } from "../lib/scan";

// ts-lint: disable no-console
(async () => {
  const args = commandLineArgs([
    { name: "path", type: String }, // required
    { name: "platform", type: String }, // required, the platform of the image to be scanned
    { name: "file", type: String }, // optional Dockerfile
    { name: "exclude-app-vulns", type: Boolean },
    { name: "exclude-base-image-vulns", type: Boolean },
    { name: "nested-jar-depth", type: Number }, // level of JAR unpacking to perform
    { name: "username", type: String }, // creds for private docker repos
    { name: "password", type: String }, // creds for private docker repos
  ]);

  if (!args.path || !args.platform) {
    console.log(
      "ERROR: You must supply both --path && --platform args to the debug script",
    );
    process.exit();
  }

  debugger;

  try {
    const response = await scan(args);
    const json = JSON.stringify(response);
    console.log(json);
  } catch (err) {
    console.log(err);
  }
})();
