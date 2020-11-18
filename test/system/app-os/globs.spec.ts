import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("find globs tests", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "debian@sha256:f520e4a80b736389c3de162b8f60608d11c9fa3b2ec619bd40aabfd7e70d3455",
    ]).catch();
  });

  it("should correctly return manifest files when detected by globs", async () => {
    const image =
      "debian@sha256:f520e4a80b736389c3de162b8f60608d11c9fa3b2ec619bd40aabfd7e70d3455";
    const pluginResult = await scan({
      path: image,
      globsToFind: {
        include: ["**/os-release"],
        exclude: [],
      },
    });

    expect(pluginResult).toMatchSnapshot();
  });
});
