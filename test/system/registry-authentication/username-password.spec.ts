import { EOL } from "os";
import { scan } from "../../../lib/index";

describe("username and password authentication", () => {
  it("should correctly authenticate to the container registry when username and password are provided", async () => {
    const pluginResult = await scan({
      path: process.env.DOCKER_HUB_PRIVATE_IMAGE,
      username: process.env.DOCKER_HUB_USERNAME,
      password: process.env.DOCKER_HUB_PASSWORD,
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
    ).rejects.toEqual(
      Error(`{"details":"incorrect username or password"}${EOL}`),
    );
  });
});
