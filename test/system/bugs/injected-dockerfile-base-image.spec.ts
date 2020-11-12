import { join as pathJoin } from "path";

import { scan } from "../../../lib/index";

describe("demonstrates a bug with detecting injected Dockerfile base image name and tag", () => {
  it("returns null:null for base image analysis if the parameters are injected in the Dockerfile", async () => {
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

    expect(dockerfileAnalysis).toMatchObject(
      expect.objectContaining({
        // This is the bug!
        baseImage: "null:null",
      }),
    );
  });
});
