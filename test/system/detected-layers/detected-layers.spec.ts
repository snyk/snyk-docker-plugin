import { readFileSync } from "fs";
import * as path from "path";
import { scan } from "../../../lib";
import { analyseDockerfile } from "../../../lib/dockerfile";
import { extractImageContent } from "../../../lib/extractor";
import {
  getDetectedLayersInfoFromConfig,
  getUserInstructionLayersFromConfig,
} from "../../../lib/extractor/docker-archive/index";
import { ExtractAction } from "../../../lib/extractor/types";
import { AutoDetectedUserInstructions, ImageType } from "../../../lib/types";
import { getFixture, getObjFromFixture } from "../../util";

const expectedNginxPackages = [
  "gnupg1",
  "ca-certificates",
  "nginxPackages",
  "gettext-base",
].sort();

describe("auto detected layers are identical to dockerfileAnlaysis layert", () => {
  const cases = ["nginx"];
  test.each(cases)(
    "%p -  detected packages are identical to dockerfile layers",
    async (image) => {
      const dockerfilePath = path.join(
        __dirname,
        `../../fixtures/dockerfiles/library/${image}/Dockerfile`,
      );

      const dockerfileAnalysis = await analyseDockerfile(
        readFileSync(dockerfilePath, "utf8"),
      );

      const configPath = path.join(
        __dirname,
        `../../fixtures/image-configs/${image}.json`,
      );

      const config = JSON.parse(readFileSync(configPath, "utf8"));

      const autoDetectedUserInstructions =
        getDetectedLayersInfoFromConfig(config);

      expect(Object.keys(dockerfileAnalysis.dockerfilePackages)).toEqual(
        Object.keys(autoDetectedUserInstructions.dockerfilePackages),
      );
      expect(dockerfileAnalysis.dockerfileLayers.length).toEqual(
        autoDetectedUserInstructions.dockerfileLayers.length,
      );
    },
  );
});

describe("correctly picks user instruction layers from manifest config", () => {
  it("simple config", async () => {
    const config = getObjFromFixture("/image-configs/gcc.json");
    const layers = getUserInstructionLayersFromConfig(config);
    expect(layers.length).toBe(2);
    expect(layers).toEqual(config.history.slice(-2));
  });

  it("returns empty layers if only base image layers exist", async () => {
    const layers = getUserInstructionLayersFromConfig(
      getObjFromFixture("/image-configs/no-user-instructions.json"),
    );
    expect(layers.length).toBe(0);
  });
});

describe("layers are extracted", () => {
  it("correctly gets user instruction layers from simple dockerfile", async () => {
    const returnedContent = "this is a mock";
    const actionName = "find_mock";

    const extractActions: ExtractAction[] = [
      {
        actionName,
        filePathMatches: (filePath) => filePath === "/snyk/mock.txt",
        callback: async () => returnedContent,
      },
    ];

    const dockerResult = await extractImageContent(
      ImageType.DockerArchive,
      getFixture("docker-archives/docker-save/nginx.tar"),
      extractActions,
    );

    expect(dockerResult.autoDetectedUserInstructions).toBeDefined();
    const packages = Object.keys(
      dockerResult.autoDetectedUserInstructions.dockerfilePackages,
    ).sort();
    expect(packages).toEqual(expectedNginxPackages);
    expect(
      Object.keys(dockerResult.autoDetectedUserInstructions.dockerfileLayers)
        .length,
    ).toBe(1);
  });
});

describe("scan results", () => {
  it("returns detectedLayers fact", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
    const pluginResponse = await scan({
      path: `docker-archive:${fixturePath}`,
    });

    const autoDetectedUserInstructions: AutoDetectedUserInstructions =
      pluginResponse.scanResults[0].facts.find(
        (fact) => fact.type === "autoDetectedUserInstructions",
      )!.data;

    const packages = Object.keys(
      autoDetectedUserInstructions.dockerfilePackages,
    ).sort();
    expect(packages).toEqual(expectedNginxPackages);
    expect(
      Object.keys(autoDetectedUserInstructions.dockerfileLayers).length,
    ).toBe(1);
  });
});
