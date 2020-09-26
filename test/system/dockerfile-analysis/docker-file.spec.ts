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
    const dockerfilePath = pathJoin(__dirname, "docker-file.dockerfile");

    const pluginResult = await scan({
      path: imageNameAndTag,
      file: dockerfilePath,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
