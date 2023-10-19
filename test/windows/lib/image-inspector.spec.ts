import * as plugin from "../../../lib";
import { Docker } from "../../../lib/docker";
import * as subProcess from "../../../lib/sub-process";

describe("image-inspector", () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  test("pull image from container registry plugin", async () => {
    const imageNameAndTag = "nginx:1.19.0";

    const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");
    jest.spyOn(subProcess, "execute").mockImplementation(() => {
      throw new Error("");
    });

    await plugin.scan({
      path: imageNameAndTag,
    });

    expect(dockerPullSpy).toHaveBeenCalledTimes(1);
  });
});
