import { extractImageContent } from "../../../lib/extractor";
import { getRedHatReposContentAction } from "../../../lib/inputs/rhel/static";
import { ImageType } from "../../../lib/types";
import { getFixture } from "../../util/index";

describe("extractImageContent", () => {
  it("extracts red hat repositories information from layers", async () => {
    const extractedContent = await extractImageContent(
      ImageType.DockerArchive,
      getFixture("docker-archives/docker-save/nginx-with-buildinfo.tar"),
      [getRedHatReposContentAction],
    );

    const numOfFoundFiles = Object.keys(extractedContent.extractedLayers)
      .length;
    expect(numOfFoundFiles).toBe(1);

    expect(
      extractedContent.extractedLayers[
        "/root/buildinfo/content_manifests/jenkins-agent-maven-35-rhel7-container-v3.11.346-2.json"
      ]["redhat-content-manifests"],
    ).toMatchObject({
      metadata: {
        icm_version: 1,
        icm_spec:
          "https://raw.githubusercontent.com/containerbuildsystem/atomic-reactor/master/atomic_reactor/schemas/content_manifest.json",
        image_layer_index: 6,
      },
      content_sets: [
        "rhel-7-server-ose-3.11-rpms",
        "rhel-server-rhscl-7-rpms",
        "rhel-7-server-rpms",
      ],
      image_contents: [],
    });
  });
});
