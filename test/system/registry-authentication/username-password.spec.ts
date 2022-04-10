import { scan } from "../../../lib/index";

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
