import * as rpmParser from "@snyk/rpm-parser";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import * as fs from "fs";
import { ExtractedLayers } from "../../../../../lib/extractor/types";
import {
  getRpmDbFileContent,
  getRpmNdbFileContent,
} from "../../../../../lib/inputs/rpm/static";
import { streamToBuffer } from "../../../../../lib/stream-utils";

describe("test getRpmNdbFileContent", () => {
  it("should return an empty array when layers are null", async () => {
    const extractedLayers: ExtractedLayers = {};
    const result = await getRpmNdbFileContent(extractedLayers);
    expect(result).toEqual([]);
  });

  it("should return an empty array when rpm ndb database file is an empty buffer", async () => {
    const extractedLayers: ExtractedLayers = {
      "/usr/lib/sysimage/rpm/Packages.db": { "rpm-ndb": Buffer.from("") },
    };
    const result = await getRpmNdbFileContent(extractedLayers);
    expect(result).toEqual([]);
  });

  it("should return an empty array when getPackagesNdb returns an error in the response", async () => {
    const extractedLayers: ExtractedLayers = {
      "/usr/lib/sysimage/rpm/Packages.db": {
        "rpm-ndb": Buffer.from("invalid ndb format"),
      },
    };
    const result = await getRpmNdbFileContent(extractedLayers);
    expect(result).toEqual([]);
  });

  it("should return an array of PackageInfo when Packages.db ndb file contains valid data", async () => {
    const rpmPackages: PackageInfo[] = [
      {
        name: "system-user-root",
        version: "20190513",
        release: "3.3.1",
        size: 186,
        arch: "noarch",
        sourceRPM: "system-user-root-20190513-3.3.1.src.rpm",
      },
      {
        name: "filesystem",
        version: "15.0",
        release: "11.8.1",
        size: 535,
        arch: "x86_64",
        sourceRPM: "filesystem-15.0-11.8.1.src.rpm",
      },
      {
        name: "glibc",
        version: "2.31",
        release: "150300.63.1",
        size: 6462759,
        arch: "x86_64",
        sourceRPM: "glibc-2.31-150300.63.1.src.rpm",
      },
    ];
    const rpmNdbStream = fs.createReadStream(
      "test/unit/lib/inputs/rpm/Packages.db",
    );
    const rpmNdbBuffer = await streamToBuffer(rpmNdbStream);

    const extractedLayers: ExtractedLayers = {
      "/usr/lib/sysimage/rpm/Packages.db": { "rpm-ndb": rpmNdbBuffer },
    };
    const rpmPackagesInfo = await getRpmNdbFileContent(extractedLayers);
    expect(rpmPackagesInfo).toEqual(rpmPackages);
  });
});
