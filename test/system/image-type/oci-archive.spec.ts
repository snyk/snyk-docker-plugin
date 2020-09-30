import { join as pathJoin } from "path";
import { scan } from "../../../lib/index";

function getFixture(fixturePath: string): string {
  return pathJoin(__dirname, "../../fixtures", fixturePath);
}

describe("oci archive scanning", () => {
  it("should correctly scan an oci archive", async () => {
    const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
    const imageNameAndTag = `oci-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
    });

    expect(pluginResult).toMatchSnapshot();
  });
});

describe("handles bad input being provided", () => {
  it("should reject when provided with a non-existent oci-archive", async () => {
    await expect(() =>
      scan({
        path: "oci-archive:not-here.tar",
      }),
    ).rejects.toEqual(
      Error("The provided archive path does not exist on the filesystem"),
    );
  });
});
