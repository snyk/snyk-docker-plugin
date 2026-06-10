import { Docker } from "../../../lib/docker";
import { scan } from "../../../lib/index";

// Force the plugin down the registry-API pull path (pullFromContainerRegistry),
// which is what these snapshots were recorded from and the only path that uses
// the credentials under test. Without this, the suite failed on developer
// machines while passing in CI: scan() prefers `docker save` when the image is
// already in the local daemon, and otherwise shells out to a plain
// `docker pull` that authenticates with the developer's own `docker login`.
// On both of those paths the credentials passed to scan() are ignored (so bad
// credentials were never rejected) and the resulting imageLayers/imageNames
// facts don't match the snapshots.
beforeAll(() => {
  jest.spyOn(Docker, "binaryExists").mockResolvedValue(false);
  jest
    .spyOn(Docker.prototype, "inspectImage")
    .mockRejectedValue(new Error("forcing registry pull in tests"));
});

describe("username and password authentication", () => {
  const oldSnykRegistryUsernameEnvVar = process.env.SNYK_REGISTRY_USERNAME;
  const oldSnykRegistryPasswordEnvVar = process.env.SNYK_REGISTRY_PASSWORD;

  afterAll(() => {
    // return SNYK credential env vars to previous state
    if (oldSnykRegistryUsernameEnvVar !== undefined) {
      process.env.SNYK_REGISTRY_USERNAME = oldSnykRegistryUsernameEnvVar;
    }
    if (oldSnykRegistryPasswordEnvVar !== undefined) {
      process.env.SNYK_REGISTRY_PASSWPRD = oldSnykRegistryPasswordEnvVar;
    }
  });

  it("should correctly authenticate to the container registry when username and password are provided as flags", async () => {
    const pluginResult = await scan({
      path: process.env.DOCKER_HUB_PRIVATE_IMAGE,
      username: process.env.DOCKER_HUB_USERNAME,
      password: process.env.DOCKER_HUB_PASSWORD,
    });

    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly authenticate to the container registry when username and password are provided as SNYK env vars and not as flags", async () => {
    process.env.SNYK_REGISTRY_USERNAME = process.env.DOCKER_HUB_USERNAME;
    process.env.SNYK_REGISTRY_PASSWORD = process.env.DOCKER_HUB_PASSWORD;

    const pluginResult = await scan({
      path: process.env.DOCKER_HUB_PRIVATE_IMAGE,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

describe("handles bad input being provided", () => {
  it("should reject when provided with bad credentials", async () => {
    await expect(() =>
      scan({
        path: process.env.DOCKER_HUB_PRIVATE_IMAGE,
        username: "foo",
        password: "bar",
      }),
    ).rejects.toEqual(Error(`{"details":"incorrect username or password"}`));
  });
});
