import { Docker } from "../../../lib/docker";
import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

const inspectImageSpy = jest.spyOn(Docker.prototype, "inspectImage");
const binaryExistsSpy = jest.spyOn(Docker, "binaryExists");

describe("image layers consistency", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "debian:stable-20200803-slim",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should return identical image layers when pulling with docker and with pull library", async () => {
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

    expect(dockerImageLayers).toEqual(pullLibraryImageLayers);

    inspectImageMock.mockRestore();
    binaryExistsMock.mockRestore();
  });
});
