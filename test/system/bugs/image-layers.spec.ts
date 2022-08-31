import { Docker } from "../../../lib/docker";
import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

const inspectImageSpy = jest.spyOn(Docker.prototype, "inspectImage");
const binaryExistsSpy = jest.spyOn(Docker, "binaryExists");

describe("demonstrates a potential bug with image layers", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "debian:stable-20200803-slim",
    ]).catch();
  });

  /** This bug potentially lies in the pull library. */
  it("should return different image layers when pulling with docker and with pull library", async () => {
    const image = "debian:stable-20200803-slim";
    const dockerPluginResult = await scan({
      path: image,
    });

    const inspectImageMock = inspectImageSpy.mockRejectedValue(
      new Error("Mock error"),
    );
    const binaryExistsMock = binaryExistsSpy.mockResolvedValue(false);
    const pullLibraryPluginResult = await scan({
      path: image,
    });

    const dockerImageLayers: string[] =
      dockerPluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "imageLayers",
      )!.data;
    const pullLibraryImageLayers: string[] =
      pullLibraryPluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "imageLayers",
      )!.data;
    expect(dockerImageLayers).toBeDefined();
    expect(pullLibraryImageLayers).toBeDefined();

    // BUG: The layers should be identical!
    expect(dockerImageLayers).not.toEqual(pullLibraryImageLayers);

    inspectImageMock.mockRestore();
    binaryExistsMock.mockRestore();
  });
});
