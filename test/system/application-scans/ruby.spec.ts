import { scan } from "../../../lib";
import { ImageManifestFilesFact } from "../../../lib/facts";
import { getFixture } from "../../util";

describe("ruby application scans", () => {
  it("should correctly return applications", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/gemfile.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imageNameAndTag,
      "app-vulns": true,
      globsToFind: {
        include: ["**/Gemfile", "**/Gemfile.lock"],
        exclude: [],
      },
    });

    expect(pluginResult.scanResults.length).toBeGreaterThan(0);

    const imageManifestFiles = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageManifestFiles",
    )! as ImageManifestFilesFact;
    expect(imageManifestFiles).toBeDefined();

    const manifestFile = imageManifestFiles.data.find(
      (manifest) => manifest.name === "Gemfile.lock",
    )!;
    expect(manifestFile).toBeDefined();

    const decodedContents = Buffer.from(manifestFile.contents, "base64");
    const gemfileLock = decodedContents.toString("utf8");
    // This is testing for a specific bug with our extraction logic.
    // Previously the length would be less than half of this number due to a bug in the encoding logic.
    expect(gemfileLock.length).toEqual(28180);
  });
});
