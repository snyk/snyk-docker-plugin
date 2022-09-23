import { getRedHatRepositoriesFromExtractedLayers } from "../../../../lib/inputs/redHat/static";
import { getObjFromFixture } from "../../../util";

describe("getRedHatRepositoriesFromExtractedLayers", () => {
  it("returns unique set of repositories from rhel7 image", () => {
    const extractedLayers = getObjFromFixture(
      "extracted-layers/rhel7-with-content-manifests.json",
    );

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toMatchObject([
      "rhel-7-server-ose-3.11-rpms",
      "rhel-server-rhscl-7-rpms",
      "rhel-7-server-rpms",
    ]);
  });

  it("returns unique set of repositories from ubi8 image", () => {
    const extractedLayers = getObjFromFixture(
      "extracted-layers/ubi8-with-content-manifests.json",
    );

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toMatchObject([
      "rhel-8-for-x86_64-baseos-rpms",
      "rhel-8-for-x86_64-appstream-rpms",
      "rhel-8-for-x86_64-baseos-beta-rpms",
      "rhel-8-for-x86_64-appstream-beta-rpms",
      "rhel-8-for-x86_64-baseos-htb-rpms",
      "rhel-8-for-x86_64-appstream-htb-rpms",
    ]);
  });
});
