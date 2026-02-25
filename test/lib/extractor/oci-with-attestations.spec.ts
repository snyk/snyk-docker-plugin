import { extractImageContent } from "../../../lib/extractor";
import { ImageType } from "../../../lib/types";
import { getFixture } from "../../util/index";

describe("OCI archive with attestation blobs", () => {
  const fixture = getFixture("oci-archives/oci-with-attestations.tar");
  const opts = { platform: "linux/amd64" };

  it("successfully extracts layers without deadlocking on large attestation blobs", async () => {
    const result = await extractImageContent(
      ImageType.OciArchive,
      fixture,
      [],
      opts,
    );
    expect(result.manifestLayers.length).toBe(1);
    expect(result.extractedLayers).toBeDefined();
    expect(result.imageId).toContain("sha256:");
  });

  it("extracts when image type is unset (fallback path)", async () => {
    await expect(
      extractImageContent(0, fixture, [], opts),
    ).resolves.not.toThrow();
  });

  it("returns correct platform from image config", async () => {
    const result = await extractImageContent(
      ImageType.OciArchive,
      fixture,
      [],
      opts,
    );
    expect(result.platform).toBe("linux/amd64");
  });

  it("returns rootfs layer diff IDs", async () => {
    const result = await extractImageContent(
      ImageType.OciArchive,
      fixture,
      [],
      opts,
    );
    expect(result.rootFsLayers).toBeDefined();
    expect(result.rootFsLayers!.length).toBe(1);
  });

  it("extracts layer file content via extract actions", async () => {
    const extractActions = [
      {
        actionName: "read_hello",
        filePathMatches: (filePath: string) => filePath.endsWith("hello.txt"),
        callback: async (stream: NodeJS.ReadableStream) => {
          const chunks: Buffer[] = [];
          for await (const chunk of stream) {
            chunks.push(chunk as Buffer);
          }
          return chunks.join("");
        },
      },
    ];

    const result = await extractImageContent(
      ImageType.OciArchive,
      fixture,
      extractActions,
      opts,
    );

    const helloContent = result.extractedLayers["/hello.txt"].read_hello;
    expect(helloContent).toBe("hello\n");
  });
});
