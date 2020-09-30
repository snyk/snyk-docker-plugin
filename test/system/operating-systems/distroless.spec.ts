import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("distroless tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "gcr.io/distroless/base-debian10@sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf",
    ]).catch();
  });

  it("should correctly analyze a distroless image by sha256", async () => {
    const image =
      "gcr.io/distroless/base-debian10@sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf";
    const pluginResult = await scan({
      path: image,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
