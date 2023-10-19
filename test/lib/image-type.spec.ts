import { getArchivePath, getImageType } from "../../lib/image-type";
import { ImageType } from "../../lib/types";

describe("image-type", () => {
  describe("getImageType", () => {
    test("should return plain image identifier type given plain image", () => {
      const image = "nginx:latest";
      const expectedImageType = ImageType.Identifier;

      const result = getImageType(image);

      expect(result).toEqual(expectedImageType);
    });

    test("should return docker-archive type given docker-archive image", () => {
      const image = "docker-archive:/tmp/nginx.tar";
      const expectedImageType = ImageType.DockerArchive;

      const result = getImageType(image);

      expect(result).toEqual(expectedImageType);
    });

    test("should return oci-archive type given oci-archive image", () => {
      const image = "oci-archive:/tmp/nginx.tar";
      const expectedImageType = ImageType.OciArchive;

      const result = getImageType(image);

      expect(result).toEqual(expectedImageType);
    });
  });

  describe("getArchivePath", () => {
    test("should return extracted path from docker-archive target image given docker-archive image path", () => {
      const imagePath = "docker-archive:/tmp/nginx.tar";
      const expectedArchivePath = "/tmp/nginx.tar";

      const result = getArchivePath(imagePath);

      expect(result).toEqual(expectedArchivePath);
    });

    test("should return extracted path from oci-archive target image given oci-archive image path", () => {
      const targetImage = "oci-archive:/tmp/nginx.tar";
      const expectedArchivePath = "/tmp/nginx.tar";

      const result = getArchivePath(targetImage);

      expect(result).toEqual(expectedArchivePath);
    });

    test("should throws error given bad path provided", () => {
      const targetImage = "bad-pathr";
      const expectedErrorMessage =
        'The provided archive path is missing a prefix, for example "docker-archive:" or "oci-archive:"';

      expect(() => {
        getArchivePath(targetImage);
      }).toThrowError(expectedErrorMessage);
    });
  });
});
