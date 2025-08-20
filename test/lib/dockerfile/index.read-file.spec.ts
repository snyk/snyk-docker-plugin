import * as fs from "fs";
import { EOL } from "os";
import {
  analyseDockerfile,
  readDockerfileAndAnalyse,
} from "../../../lib/dockerfile";

jest.mock("fs");

describe("dockerfile index: read and analyse", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  it("analyseDockerfile returns expected structure", async () => {
    const contents = ["FROM repo:tag", "RUN apk add curl"].join(EOL);

    const result = await analyseDockerfile(contents);
    expect(result.baseImage).toBe("repo:tag");
    expect(result.error).toBeUndefined();
    expect(result.dockerfilePackages).toHaveProperty("curl");
    expect(result.dockerfileLayers).toBeDefined();
  });

  it("readDockerfileAndAnalyse returns undefined when path is missing", async () => {
    const res = await readDockerfileAndAnalyse(undefined);
    expect(res).toBeUndefined();
  });

  it("readDockerfileAndAnalyse reads file and analyses content", async () => {
    const contents = "FROM alpine\nRUN apk add bash";
    (fs.readFile as unknown as jest.Mock).mockImplementation((_p, _enc, cb) =>
      cb(null, contents),
    );

    const res = await readDockerfileAndAnalyse("/tmp/Dockerfile");
    expect(fs.readFile).toHaveBeenCalled();
    expect(res?.baseImage).toBe("alpine");
    expect(res?.dockerfilePackages).toHaveProperty("bash");
  });

  it("readDockerfileAndAnalyse surfaces read errors", async () => {
    (fs.readFile as unknown as jest.Mock).mockImplementation((_p, _enc, cb) =>
      cb(new Error("boom"), undefined),
    );

    await expect(
      readDockerfileAndAnalyse("/bad/path/Dockerfile"),
    ).rejects.toThrow("boom");
  });
});
