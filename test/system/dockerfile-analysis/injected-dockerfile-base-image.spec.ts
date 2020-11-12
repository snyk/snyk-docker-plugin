import { join as pathJoin } from "path";
import { DockerFileAnalysis } from "../../../lib/dockerfile";
import { scan } from "../../../lib/index";

describe("detecting injected Dockerfile base image name and tag", () => {
  it("returns undefined for base image analysis if the parameters are injected in the Dockerfile", async () => {
    const imagePath = pathJoin(
      __dirname,
      "../../fixtures/docker-archives/docker-save/hello-world.tar",
    );
    const dockerfilePath = pathJoin(__dirname, "Dockerfile.injected");

    const pluginResult = await scan({
      path: `docker-archive:${imagePath}`,
      file: dockerfilePath,
    });

    const dockerfileAnalysis = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "dockerfileAnalysis",
    )?.data;

    expect(dockerfileAnalysis).toMatchObject<DockerFileAnalysis>({
      baseImage: undefined,
      dockerfilePackages: expect.any(Object),
      dockerfileLayers: expect.any(Object),
    });
  });
});
