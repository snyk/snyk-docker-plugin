import { Docker } from "../../../lib/docker";
import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

// The image is private, so force the registry-API pull path the snapshot was
// recorded from. Without this, the suite failed on developer machines while
// passing in CI: a locally cached copy of the image (or a successful
// `docker pull` via the developer's own `docker login`) makes scan() use
// `docker save` instead, which produces different imageLayers/imageNames
// facts than the registry pull.
beforeAll(() => {
  jest.spyOn(Docker, "binaryExists").mockResolvedValue(false);
  jest
    .spyOn(Docker.prototype, "inspectImage")
    .mockRejectedValue(new Error("forcing registry pull in tests"));
});

describe("chisel package manager tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "snykgoof/dockerhub-goof:ubuntu-chisel-24.04",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly analyze a chiseled Ubuntu image", async () => {
    const image = "snykgoof/dockerhub-goof:ubuntu-chisel-24.04";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
      username: process.env.DOCKER_HUB_USERNAME,
      password: process.env.DOCKER_HUB_PASSWORD,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
