import { getRedHatReposFromExtractedLayers } from "../../../../lib/inputs/rhel/static";
import { getObjFromFixture } from "../../../util";

describe("getRedHatReposFromExtractedLayers()", () => {
  it("correctly gets list of repos and image layer index", () => {
    const extractedLayers = getObjFromFixture(
      "extracted-layers/with-content-manifests.json",
    );

    const repos = getRedHatReposFromExtractedLayers(extractedLayers);
    expect(repos).toMatchObject({
      "6": [
        "rhel-7-server-ose-3.11-rpms",
        "rhel-server-rhscl-7-rpms",
        "rhel-7-server-rpms",
      ],
    });
  });
});
