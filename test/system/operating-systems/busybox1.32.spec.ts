import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("busybox tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "busybox@sha256:32dc7202280d641c9c0d94a13247195adc83dba83aca0eed383888c01311cfc2",
    ]).catch();
  });

  it("should correctly analyze a busybox image by sha256", async () => {
    const image =
      "busybox@sha256:32dc7202280d641c9c0d94a13247195adc83dba83aca0eed383888c01311cfc2";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
