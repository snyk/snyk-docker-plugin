import * as fs from "fs";
import * as path from "path";
import * as tmp from "tmp";
import { v4 as uuidv4 } from "uuid";

import { DockerPullResult } from "@snyk/snyk-docker-pull";
import * as plugin from "../../../lib";
import * as imageInspector from "../../../lib/analyzer/image-inspector";
import { ArchiveResult } from "../../../lib/analyzer/types";
import { Docker } from "../../../lib/docker";
import * as subProcess from "../../../lib/sub-process";

function rmdirRecursive(customPath: string[]): void {
  if (customPath.length < 2) {
    return;
  }

  const joinedPath = path.join(...customPath);
  fs.rmSync(joinedPath, { recursive: true, force: true });
}

// prettier-ignore
describe("extractImageDetails", () => {
  it.each`
  
    image | expected
    
    ${"hello-world"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "library/hello-world",
      tag: "latest",
    }}
    ${"gcr.io/kubernetes/someImage:alpine"} | ${{
      hostname: "gcr.io",
      imageName: "kubernetes/someImage",
      tag: "alpine",
    }}
    ${"nginx:1.18"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "library/nginx",
      tag: "1.18",
    }}
    ${"nginx:1.18"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "library/nginx",
      tag: "1.18",
    }}
    ${"calico/cni:release-v3.14"} | ${{
      hostname: "registry-1.docker.io",
      imageName: "calico/cni",
      tag: "release-v3.14",
    }}
    ${"gcr.io:3000/kubernetes/someImage:alpine"} | ${{
      hostname: "gcr.io:3000",
      imageName: "kubernetes/someImage",
      tag: "alpine",
    }}
    ${"localhost/alpine"} | ${{
      hostname: "localhost",
      imageName: "alpine",
      tag: "latest",
    }}
    ${"localhost:1337/kubernetes/someImage:alpine"} | ${{
      hostname: "localhost:1337",
      imageName: "kubernetes/someImage",
      tag: "alpine",
    }}
    ${"gcr.io/distroless/base-debian10@sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf"} | ${{
      hostname: "gcr.io",
      imageName: "distroless/base-debian10",
      tag: "sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf",
    }}
    ${"localhost:1234/foo/bar@sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf"} | ${{
      hostname: "localhost:1234",
      imageName: "foo/bar",
      tag: "sha256:8756a25c4c5e902c4fe20322cc69d510a0517b51eab630c614efbd612ed568bf",
    }}
  `("extract details for $image", async ({ image, expected }) => {
    const {
      hostname,
      imageName,
      tag,
    } = await imageInspector.extractImageDetails(image);
    expect(hostname).toEqual(expected.hostname);
    expect(imageName).toEqual(expected.imageName);
    expect(tag).toEqual(expected.tag);
  });
  it("should throw an error if the image name has an invalid format", async () => {
     const imageNameAndTag = "/test:unknown";

     await expect(() =>
       plugin.scan({
         path: imageNameAndTag,
       }),
     ).rejects.toEqual(
       new Error("invalid image format"),
     );
   });
});

describe("getImageArchive", () => {
  const targetImage = "library/hello-world:latest";

  describe("from the local daemon if it exists", () => {
    const customPath = "./other_custom/image/save/path/local/daemon";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");
      const loadImage = path.join(
        __dirname,
        "../../fixtures/docker-archives",
        "docker-save/hello-world.tar",
      );
      await subProcess.execute("docker", ["load", "--input", loadImage]);
      const archiveLocation = await imageInspector.getImageArchive(
        targetImage,
        imageSavePath,
      );

      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      expect(dockerPullSpy).not.toHaveBeenCalled();

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);
    });
  });

  describe("from remote registry with binary", () => {
    afterEach(async () => {
      await subProcess.execute("docker", ["image", "rm", targetImage]);
    });

    it("should produce the expected state", async () => {
      const customPath = tmp.dirSync().name;
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");

      const archiveLocation: ArchiveResult = await imageInspector.getImageArchive(
        targetImage,
        imageSavePath,
      );

      expect(dockerPullSpy).not.toHaveBeenCalled();
      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);
    });
  });

  describe("from remote registry without binary", () => {
    const customPath = "./new_custom/image/save/path";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");
      jest.spyOn(subProcess, "execute").mockImplementation(() => {
        throw new Error();
      });

      const archiveLocation = await imageInspector.getImageArchive(
        targetImage,
        imageSavePath,
      );

      expect(dockerPullSpy).toHaveBeenCalled();
      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);
    });
  });

  describe("from remote registry with authentication", () => {
    const customPath = "./my_custom/image/save/path/auth";

    afterEach(() => {
      rmdirRecursive(customPath.split(path.sep));
    });

    it("should produce the expected state", async () => {
      const imageSavePath = path.join(customPath, uuidv4());
      const dockerPullSpy = jest
        .spyOn(Docker.prototype, "pull")
        .mockImplementation((_1, _2, _3, imageSavePath) => {
          fs.writeFileSync(path.join(imageSavePath, "image.tar"), "");
          return Promise.resolve({} as DockerPullResult);
        });
      jest.spyOn(subProcess, "execute").mockImplementation(() => {
        throw new Error();
      });

      const username = "someUsername";
      const password = "somePassword";

      const archiveLocation = await imageInspector.getImageArchive(
        targetImage!,
        imageSavePath,
        username,
        password,
      );

      expect(dockerPullSpy).toHaveBeenCalledWith(
        "registry-1.docker.io",
        "library/hello-world",
        "latest",
        imageSavePath,
        username,
        password,
      );
      expect(archiveLocation.path).toEqual(
        path.join(imageSavePath, "image.tar"),
      );

      // Checking the image file exists is not done to test that the mockImplementation worked,
      // but instead asserts the preconditions for removeArchive() to actually work - i.e.
      // `expect(imageExistsOnDiskAfterDelete).toBe(false);` gives us no useful assurances
      // if the image wasn't there to begin with
      const imageExistsOnDisk: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDisk).toBe(true);

      archiveLocation.removeArchive();

      const imageExistsOnDiskAfterDelete: boolean = fs.existsSync(
        path.join(imageSavePath, "image.tar"),
      );
      expect(imageExistsOnDiskAfterDelete).toBe(false);

      const tmpFolderExistsOnDisk: boolean = fs.existsSync(imageSavePath);
      expect(tmpFolderExistsOnDisk).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);
    });
  });
});
