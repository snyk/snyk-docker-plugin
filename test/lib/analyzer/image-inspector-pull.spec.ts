import { pullIfNotLocal } from "../../../lib/analyzer/image-inspector";
import { Docker } from "../../../lib/docker";

describe("image-inspector pullIfNotLocal", () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  describe("when image exists locally", () => {
    it("should return without pulling", async () => {
      const targetImage = "test-image:v1";
      const dockerInspectSpy = jest
        .spyOn(Docker.prototype, "inspectImage")
        .mockResolvedValue({} as any);
      const dockerPullSpy = jest
        .spyOn(Docker.prototype, "pullCli")
        .mockResolvedValue({ stdout: "", stderr: "" });

      await pullIfNotLocal(targetImage);

      expect(dockerInspectSpy).toHaveBeenCalledWith(targetImage);
      expect(dockerInspectSpy).toHaveBeenCalledTimes(1);
      expect(dockerPullSpy).not.toHaveBeenCalled();
    });
  });

  describe("when image does not exist locally", () => {
    it("should pull the image", async () => {
      const targetImage = "test-image:v2";
      const dockerInspectSpy = jest
        .spyOn(Docker.prototype, "inspectImage")
        .mockRejectedValue(new Error("Image not found"));
      const dockerPullSpy = jest
        .spyOn(Docker.prototype, "pullCli")
        .mockResolvedValue({ stdout: "", stderr: "" });

      await pullIfNotLocal(targetImage);

      expect(dockerInspectSpy).toHaveBeenCalledWith(targetImage);
      expect(dockerInspectSpy).toHaveBeenCalledTimes(1);
      expect(dockerPullSpy).toHaveBeenCalledWith(targetImage);
      expect(dockerPullSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe("with custom options", () => {
    it("should not pass options to pullCli (current implementation ignores options)", async () => {
      const targetImage = "test-image:v3";
      const options = { platform: "linux/amd64" };
      const dockerInspectSpy = jest
        .spyOn(Docker.prototype, "inspectImage")
        .mockRejectedValue(new Error("Image not found"));
      const dockerPullSpy = jest
        .spyOn(Docker.prototype, "pullCli")
        .mockResolvedValue({ stdout: "", stderr: "" });

      await pullIfNotLocal(targetImage, options);

      expect(dockerInspectSpy).toHaveBeenCalledWith(targetImage);
      // Note: Current implementation doesn't pass options to pullCli
      expect(dockerPullSpy).toHaveBeenCalledWith(targetImage);
    });
  });
});
