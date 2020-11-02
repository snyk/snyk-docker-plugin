import { join as pathJoin } from "path";
import { scan } from "../../../lib/index";

describe("dockerfile analysis", () => {
  it("should correctly return a dockerfile analysis as part of image scanning", async () => {
    const fixturePath = pathJoin(
      __dirname,
      "../../fixtures",
      "oci-archives/alpine-3.12.0.tar",
    );
    const imageNameAndTag = `oci-archive:${fixturePath}`;
    const dockerfilePath = pathJoin(__dirname, "Dockerfile");

    const pluginResult = await scan({
      path: imageNameAndTag,
      file: dockerfilePath,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly return annotated packages saying which docker layer introduced a package", async () => {
    const fixturePath = pathJoin(
      __dirname,
      "../../fixtures/docker-archives/docker-save/dockergoof.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;
    const dockerfilePath = pathJoin(__dirname, "Dockerfile.dockergoof");

    const pluginResult = await scan({
      path: imageNameAndTag,
      file: dockerfilePath,
      imageNameAndTag: "snyk/runtime-fixtures:dockergoof",
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
