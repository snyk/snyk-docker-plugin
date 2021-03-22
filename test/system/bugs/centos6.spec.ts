import { scan } from "../../../lib";
import { execute } from "../../../lib/sub-process";

describe("BUG: CentOS 6 image cannot be scanned", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "dokken/centos-6@sha256:494b9b280814f1e661597b48e229156e4dccb60dce198d9210f7572ff22626d2",
    ]).catch();
  });

  it("cannot scan a centos6-based image", async () => {
    const imagePath =
      "dokken/centos-6@sha256:494b9b280814f1e661597b48e229156e4dccb60dce198d9210f7572ff22626d2";

    await expect(async () =>
      scan({
        path: imagePath,
      }),
    ).rejects.toThrow("Failed to detect OS release");
  });
});
