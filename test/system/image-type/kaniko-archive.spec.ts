import { scan } from "../../../lib";
import { getFixture } from "../../util";

describe("kaniko archive scanning", () => {
  it("should correctly scan a kaniko archive", async () => {
    const fixturePath = getFixture("kaniko-archives/kaniko-busybox.tar");
    const imageNameAndTag = `kaniko-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
