import { extractImageContent } from "../../../lib/extractor";
import { ExtractionResult } from "../../../lib/extractor/types";
import { getRedHatRepositoriesContentAction } from "../../../lib/inputs/redHat/static";
import { ImageType } from "../../../lib/types";
import { getFixture } from "../../util/index";

describe("extractImageContent", () => {
  let extractedContent: ExtractionResult;

  beforeAll(async () => {
    extractedContent = await extractImageContent(
      ImageType.DockerArchive,
      getFixture("docker-archives/docker-save/nginx-with-buildinfo.tar"),
      [getRedHatRepositoriesContentAction],
      {},
    );
  });

  it("extracts image labels", async () => {
    expect(extractedContent.imageLabels).toMatchObject({
      maintainer: "NGINX Docker Maintainers <docker-maint@nginx.com>",
    });
  });

  it("extracts image creation time", async () => {
    expect(typeof extractedContent.imageCreationTime).toEqual("string");
  });

  describe("RedHat support", () => {
    it("extracts red hat repositories information from layers", async () => {
      const numOfFoundFiles = Object.keys(
        extractedContent.extractedLayers,
      ).length;
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

  describe("OCI Image Archives (expected to fall back to DockerExtractor)", () => {
    const fixture = getFixture("containerd-archives/alpine.tar");
    const opts = { platform: "linux/amd64" };

    it("successfully extracts the archive when image type is set to oci-archive", async () => {
      await expect(
        extractImageContent(ImageType.OciArchive, fixture, [], opts),
      ).resolves.not.toThrow();
    });

    it("successfully extracts the archive when image type is not set", async () => {
      await expect(
        extractImageContent(0, fixture, [], opts),
      ).resolves.not.toThrow();
    });

    it("successfully extracts the archive when image type is set to docker-archive", async () => {
      await expect(
        extractImageContent(ImageType.DockerArchive, fixture, [], opts),
      ).resolves.not.toThrow();
    });
  });

  describe("Kaniko Image Archives", () => {
    const fixture = getFixture("kaniko-archives/kaniko-busybox.tar");
    const opts = { platform: "linux/amd64" };

    it("successfully extracts the archive when image type is set to kaniko-archive", async () => {
      await expect(
        extractImageContent(ImageType.KanikoArchive, fixture, [], opts),
      ).resolves.not.toThrow();
    });
  });

  describe("Images pulled & saved with Docker Engine >= 25.x", () => {
    const type = ImageType.OciArchive;

    it("extracts when using default platform flag (linux/amd64)", async () => {
      const fixture = getFixture("docker-oci-archives/busybox.amd64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/amd64" }),
      ).resolves.not.toThrow();
    });

    it("extracts when using non-default platform flag with no variant (linux/arm64)", async () => {
      const fixture = getFixture("docker-oci-archives/busybox.arm64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/arm64" }),
      ).resolves.not.toThrow();
    });

    it("extracts when using non-default platform flag with variant (linux/arm64/v8)", async () => {
      const fixture = getFixture("docker-oci-archives/busybox.arm64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/arm64/v8" }),
      ).resolves.not.toThrow();
    });
  });

  describe("Images pulled & saved with containerd", () => {
    const type = ImageType.OciArchive;

    it("extracts when using default platform flag (--platform=linux/amd64)", async () => {
      const fixture = getFixture("containerd-archives/busybox.amd64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/amd64" }),
      ).resolves.not.toThrow();
    });

    it("extracts when single variant exist for architecture with no variant in platform tag (--platform=linux/arm64)", async () => {
      const fixture = getFixture("containerd-archives/busybox.arm64.tar");
      await expect(
        extractImageContent(type, fixture, [], { platform: "linux/arm64" }),
      ).resolves.not.toThrow();
    });

    describe("with multi-platform images", () => {
      it("extracts when multiple variants exist with same architecture in image (--platform=linux/arm/v7)", async () => {
        const fixture = getFixture("containerd-archives/busybox.multi.tar");
        await expect(
          extractImageContent(type, fixture, [], { platform: "linux/arm/v7" }),
        ).resolves.not.toThrow();
      });

      it("fails when multiple variants exist with same architecture in image with no variant is supplied (--platform=linux/arm)", async () => {
        const fixture = getFixture("containerd-archives/busybox.multi.tar");
        await expect(
          extractImageContent(type, fixture, [], { platform: "linux/arm" }),
        ).rejects.toThrow();
      });

      it("fails when variant does not exist in image (--platform=linux/arm/v4)", async () => {
        const fixture = getFixture("containerd-archives/busybox.multi.tar");
        await expect(
          extractImageContent(type, fixture, [], { platform: "linux/arm/v4" }),
        ).rejects.toThrow();
      });

      it("succeeds for single platform image containing an attestation manifest", async () => {
        const fixture = getFixture(
          "containerd-archives/busybox-single-arch-with-attestation-manifest.tar",
        );
        await expect(
          extractImageContent(type, fixture, [], {}),
        ).resolves.not.toThrow();
      });

      it("extracts the attestation manifest and its in-toto provenance layer", async () => {
        const fixture = getFixture(
          "containerd-archives/busybox-single-arch-with-attestation-manifest.tar",
        );

        const result = await extractImageContent(type, fixture, [], {});
        const attestations = result.provenanceAttestations ?? [];

        expect(attestations).toHaveLength(1);

        const [attestation] = attestations;
        expect(attestation.attestationManifestDigest).toBe(
          "sha256:c39be7154f939a9bf312c255b98ef2b46c77a0f8944b58c104570fc3bc19abb6",
        );
        expect(attestation.annotations["vnd.docker.reference.type"]).toBe(
          "attestation-manifest",
        );

        // The attestation must reference the platform image being scanned.
        const referencedDigest =
          attestation.annotations["vnd.docker.reference.digest"];
        expect(referencedDigest).toBe(
          "sha256:cf7d823e4eea96316ae629fb9a45b4211869162a5f5dc1654928c7ca530ed810",
        );

        expect(attestation.provenanceLayers).toHaveLength(1);
        const [layer] = attestation.provenanceLayers;
        expect(layer.mediaType).toBe("application/vnd.in-toto+json");
        expect(layer.digest).toBe(
          "sha256:4f62f95682318843696bbf8eb884d5c904c1f2fa70c0f0523bf2cac8f902db14",
        );

        // The raw in-toto blob must be wired onto the layer, and its subject
        // digest must match the referenced platform image.
        expect(layer.inTotoStatement).toBeDefined();
        expect(layer.inTotoStatement?.predicateType).toBe(
          "https://slsa.dev/provenance/v0.2",
        );
        expect(layer.inTotoStatement?.subject?.[0]?.digest?.sha256).toBe(
          "cf7d823e4eea96316ae629fb9a45b4211869162a5f5dc1654928c7ca530ed810",
        );
      });
    });
  });
});
