import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("demonstrates a bug with locally built images", () => {
  const imageNameAndTag = "non-existent-foo-bar-image:tag";

  afterAll(async () => {
    await execute("docker", ["image", "rm", imageNameAndTag]).catch();
  });

  it("fails to analyze an image that is present locally by trying to pull it from container registry", async () => {
    if (!process.env.CI) {
      return;
    }

    expect(process.env.DOCKER_HOST).toBeDefined();

    const dockerfilePath = __dirname;
    await execute("docker", ["build", "-t", imageNameAndTag, dockerfilePath]);

    await expect(
      async () =>
        await scan({
          path: imageNameAndTag,
        }),
    ).rejects.toThrow("authentication required");
  });
});
