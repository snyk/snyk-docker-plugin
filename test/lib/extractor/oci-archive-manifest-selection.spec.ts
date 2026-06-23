import { getManifest } from "../../../lib/extractor/oci-archive/layer";
import { OciArchiveManifest } from "../../../lib/extractor/types";

// Known, pre-existing bug: when there is no image index, getManifest() can
// return an attestation manifest because isImageManifest() only checks the
// config mediaType, which attestation manifests can share. it.failing passes
// while broken and will fail once fixed. Tracked in a separate ticket.
describe("getManifest with no image index (known broken)", () => {
  it.failing("returns the real image manifest, not the attestation", () => {
    const attestation: OciArchiveManifest = {
      schemaVersion: "2",
      config: { digest: "sha256:cfg", mediaType: "application/vnd.oci.image.config.v1+json" },
      layers: [{ digest: "sha256:intoto", mediaType: "application/vnd.in-toto+json" }],
    };
    const image: OciArchiveManifest = {
      schemaVersion: "2",
      config: { digest: "sha256:cfg2", mediaType: "application/vnd.oci.image.config.v1+json" },
      layers: [{ digest: "sha256:layer" }],
    };

    const result = getManifest(
      undefined,
      { "sha256:att": attestation, "sha256:img": image },
      {},
      { os: "linux", architecture: "amd64" },
    );

    expect(result).toBe(image);
  });
});
