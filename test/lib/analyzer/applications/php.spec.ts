import { phpFilesToScannedProjects } from "../../../../lib/analyzer/applications/php";

jest.mock("@snyk/composer-lockfile-parser", () => {
  return {
    buildDepTree: jest.fn((lock, manifest) => ({
      name: "root",
      version: "1.0.0",
      dependencies: {},
      type: "composer",
    })),
  };
});

describe("php analyzer", () => {
  it("returns scan result for composer manifest+lock pair", async () => {
    const files = {
      "/app/composer.json": "{}",
      "/app/composer.lock": "{}",
    };
    const res = await phpFilesToScannedProjects(files);
    expect(res).toHaveLength(1);
    expect(res[0].identity.type).toBe("composer");
    expect(res[0].identity.targetFile).toBe("/app/composer.lock");
    expect(res[0].facts.find((f) => f.type === "testedFiles")).toBeDefined();
  });

  it("skips malformed lockfile errors (InvalidUserInputError)", async () => {
    const mocked = require("@snyk/composer-lockfile-parser");
    mocked.buildDepTree.mockImplementationOnce(() => {
      const {
        InvalidUserInputError,
      } = require("@snyk/composer-lockfile-parser/dist/errors");
      throw new InvalidUserInputError("bad lock");
    });
    const files = {
      "/app2/composer.json": "{}",
      "/app2/composer.lock": "bad",
    };
    const res = await phpFilesToScannedProjects(files);
    expect(res).toHaveLength(0);
  });
});
