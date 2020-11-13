import * as fs from "fs";
import * as path from "path";
import * as tmp from "tmp";
import { v4 as uuidv4 } from "uuid";

import * as imageInspector from "../../../lib/analyzer/image-inspector";
import { ArchiveResult } from "../../../lib/analyzer/types";
import { Docker } from "../../../lib/docker";
import * as subProcess from "../../../lib/sub-process";

function rmdirRecursive(customPath: string[]): void {
  if (customPath.length < 2) {
    return;
  }

  fs.rmdirSync(path.join(...customPath));
  const next = customPath.slice(0, customPath.length - 1);
  rmdirRecursive(next);
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
      const dockerPullSpy = jest.spyOn(Docker.prototype, "pull");
      jest.spyOn(subProcess, "execute").mockImplementation(() => {
        throw new Error();
      });
      const targetImage = process.env.DOCKER_HUB_PRIVATE_IMAGE;
      if (targetImage === undefined) {
        throw new Error(
          "DOCKER_HUB_PRIVATE_IMAGE environment variable is not defined",
        );
      }

      const username = process.env.DOCKER_HUB_USERNAME;
      const password = process.env.DOCKER_HUB_PASSWORD;

      const archiveLocation = await imageInspector.getImageArchive(
        targetImage!,
        imageSavePath,
        username,
        password,
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

      const tmpFolderExistsOnDisk: boolean = fs.existsSync(imageSavePath);
      expect(tmpFolderExistsOnDisk).toBe(false);

      const customPathExistsOnDisk: boolean = fs.existsSync(customPath);
      expect(customPathExistsOnDisk).toBe(true);
    });
  });
});
