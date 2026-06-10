import { Docker } from "../../../lib/docker";
import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

// The image is private; force the registry-API pull path so results match
// CI regardless of the local daemon cache or the developer's `docker login`.
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
