import * as rpmParser from "@snyk/rpm-parser";
import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import * as fs from "fs";
import { ExtractedLayers } from "../../../../../lib/extractor/types";
import {
  getRpmDbFileContent,
  getRpmNdbFileContent,
  getRpmSqliteDbFileContent,
} from "../../../../../lib/inputs/rpm/static";
import { streamToBuffer } from "../../../../../lib/stream-utils";

// Test data factory
const createTestPackage = (name: string, version: string): PackageInfo => ({
  name,
  version,
  release: "1",
  size: 100,
  arch: "x86_64",
  sourceRPM: `${name}-${version}-1.src.rpm`,
});

// Common test configurations for all RPM database types
interface RpmTestConfig {
  functionName: string;
  testFunction: (layers: ExtractedLayers) => Promise<PackageInfo[]>;
  parserMethod: keyof typeof rpmParser;
  filePath: string;
  layerKey: string;
  testData: Buffer;
  expectedPackages: PackageInfo[];
}

const rpmTestConfigs: RpmTestConfig[] = [
  {
    functionName: "getRpmDbFileContent",
    testFunction: getRpmDbFileContent,
    parserMethod: "getPackages",
    filePath: "/var/lib/rpm/Packages",
    layerKey: "rpm-db",
    testData: Buffer.from("valid rpm data"),
    expectedPackages: [createTestPackage("test-package", "1.0.0")],
  },
  {
    functionName: "getRpmSqliteDbFileContent",
    testFunction: getRpmSqliteDbFileContent,
    parserMethod: "getPackagesSqlite",
    filePath: "/var/lib/rpm/rpmdb.sqlite",
    layerKey: "rpm-sqlite-db",
    testData: Buffer.from("valid sqlite data"),
    expectedPackages: [createTestPackage("test-sqlite-package", "2.0.0")],
  },
];

// Common test suite for standard RPM database tests
describe.each(rpmTestConfigs)(
  "$functionName standard tests",
  ({
    functionName,
    testFunction,
    parserMethod,
    filePath,
    layerKey,
    testData,
    expectedPackages,
  }) => {
    afterEach(() => {
      jest.restoreAllMocks();
    });

    it("should return an empty array when layers are null", async () => {
      const extractedLayers: ExtractedLayers = {};
      const result = await testFunction(extractedLayers);
      expect(result).toEqual([]);
    });

    it("should return empty array when parser returns error in response", async () => {
      const mockParser = jest.spyOn(rpmParser, parserMethod as any);
      const testError = new Error(`${functionName} parsing failed`);
      mockParser.mockResolvedValue({
        error: testError,
        response: [],
      });

      const extractedLayers: ExtractedLayers = {
        [filePath]: {
          [layerKey]: testData,
        },
      };

      const result = await testFunction(extractedLayers);
      expect(result).toEqual([]);
    });

    it("should handle exceptions from parser and return empty array", async () => {
      const mockParser = jest.spyOn(rpmParser, parserMethod as any);
      const testError = new Error(`Unexpected ${functionName} parsing error`);
      mockParser.mockRejectedValue(testError);

      const extractedLayers: ExtractedLayers = {
        [filePath]: {
          [layerKey]: testData,
        },
      };

      const result = await testFunction(extractedLayers);
      expect(result).toEqual([]);
    });

    it("should return array of PackageInfo when file contains valid data", async () => {
      const mockParser = jest.spyOn(rpmParser, parserMethod as any);
      mockParser.mockResolvedValue({
        error: undefined,
        response: expectedPackages,
      });

      const extractedLayers: ExtractedLayers = {
        [filePath]: {
          [layerKey]: testData,
        },
      };

      const result = await testFunction(extractedLayers);
      expect(result).toEqual(expectedPackages);
    });
  },
);

// Special tests for getRpmNdbFileContent which has additional behavior
describe("getRpmNdbFileContent specific tests", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

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

  describe("error handling with stack traces", () => {
    it.each([
      { hasStack: true, description: "with stack property" },
      { hasStack: false, description: "without stack property" },
    ])("should handle error $description", async ({ hasStack }) => {
      const mockGetPackagesNdb = jest.spyOn(rpmParser, "getPackagesNdb");
      const testError = new Error("NDB parsing failed");

      if (hasStack) {
        testError.stack = "Error: NDB parsing failed\n    at test";
      } else {
        delete testError.stack;
      }

      mockGetPackagesNdb.mockRejectedValue(testError);

      const extractedLayers: ExtractedLayers = {
        "/usr/lib/sysimage/rpm/Packages.db": {
          "rpm-ndb": Buffer.from("some ndb data"),
        },
      };

      const result = await getRpmNdbFileContent(extractedLayers);
      expect(result).toEqual([]);
    });
  });

  it("should handle exceptions from getPackagesNdb and return empty array", async () => {
    const mockGetPackagesNdb = jest.spyOn(rpmParser, "getPackagesNdb");
    const testError = new Error("Unexpected NDB parsing error");
    mockGetPackagesNdb.mockRejectedValue(testError);

    const extractedLayers: ExtractedLayers = {
      "/usr/lib/sysimage/rpm/Packages.db": {
        "rpm-ndb": Buffer.from("some ndb data"),
      },
    };

    const result = await getRpmNdbFileContent(extractedLayers);
    expect(result).toEqual([]);
  });
});
