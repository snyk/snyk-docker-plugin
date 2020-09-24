// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";
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

test("image id", async (t) => {
  const expectedId =
    "sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b393902f";
  const expectedLayers = [
    "sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b3939021",
    "sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b3939022",
    "sha256:93f518ec2c41722d6c21e55f96cef4dc4c9ba521cab51a757b1d7272b3939023",
  ];

  const stubbedData = [
    {
      Id: expectedId,
      RootFS: {
        Layers: expectedLayers,
      },
      MoreStuff: "stuff",
    },
  ];

  const execStub = sinon.stub(subProcess, "execute");
  execStub
    .withArgs("docker", ["inspect", "alpine:2.6"])
    .resolves({ stdout: JSON.stringify(stubbedData), stderr: "" });
  t.teardown(() => execStub.restore());

  const imageData = await imageInspector.detect("alpine:2.6");
  t.same(imageData.Id, expectedId, "id as expected");
  t.same(imageData.RootFS.Layers, expectedLayers, "layers as expected");
});

test("extract image details", async (t) => {
  const tests = {
    "hello-world": {
      expected: {
        hostname: "registry-1.docker.io",
        imageName: "library/hello-world",
        tag: "latest",
      },
    },
    "gcr.io/kubernetes/someImage:alpine": {
      expected: {
        hostname: "gcr.io",
        imageName: "kubernetes/someImage",
        tag: "alpine",
      },
    },
    "nginx:1.18": {
      expected: {
        hostname: "registry-1.docker.io",
        imageName: "library/nginx",
        tag: "1.18",
      },
    },
    "calico/cni:release-v3.14": {
      expected: {
        hostname: "registry-1.docker.io",
        imageName: "calico/cni",
        tag: "release-v3.14",
      },
    },
    "gcr.io:3000/kubernetes/someImage:alpine": {
      expected: {
        hostname: "gcr.io:3000",
        imageName: "kubernetes/someImage",
        tag: "alpine",
      },
      "localhost/alpine": {
        expected: {
          hostname: "localhost",
          imageName: "alpine",
          tag: "latest",
        },
      },
      "localhost:1337/kubernetes/someImage:alpine": {
        expected: {
          hostname: "localhost:1337",
          imageName: "kubernetes/someImage",
          tag: "alpine",
        },
      },
    },
  };

  for (const image of Object.keys(tests)) {
    const testCase = tests[image];
    const {
      hostname,
      imageName,
      tag,
    } = await imageInspector.extractImageDetails(image);
    t.equal(hostname, testCase.expected.hostname);
    t.equal(imageName, testCase.expected.imageName);
    t.equal(tag, testCase.expected.tag);
  }
});

test("get image as an archive", async (t) => {
  const targetImage = "library/hello-world:latest";

  t.test("from the local daemon if it exists", async (t) => {
    const customPath = "./other_custom/image/save/path/local/daemon";
    const imageSavePath = path.join(customPath, uuidv4());
    const dockerPullSpy = sinon.spy(Docker.prototype, "pull");
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

    t.teardown(async () => {
      dockerPullSpy.restore();
      rmdirRecursive(customPath.split(path.sep));
    });

    t.equal(
      archiveLocation.path,
      path.join(imageSavePath, "image.tar"),
      "expected full image path",
    );
    t.ok(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image exists on disk",
    );
    t.false(dockerPullSpy.called, "image was not pulled from remote registry");

    archiveLocation.removeArchive();
    t.notOk(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image should not exists on disk",
    );
    t.notOk(
      fs.existsSync(imageSavePath),
      "tmp folder should not exist on disk",
    );
    t.ok(fs.existsSync(customPath), "custom path should exist on disk");
  });

  t.test("from remote registry with binary", async (t) => {
    const customPath = tmp.dirSync().name;
    const imageSavePath = path.join(customPath, uuidv4());
    const dockerPullSpy = sinon.spy(Docker.prototype, "pull");

    const archiveLocation: ArchiveResult = await imageInspector.getImageArchive(
      targetImage,
      imageSavePath,
    );

    t.teardown(async () => {
      dockerPullSpy.restore();
      await subProcess.execute("docker", ["image", "rm", targetImage]);
    });

    t.true(
      dockerPullSpy.notCalled,
      "image pulled from remote registry with binary",
    );
    t.equal(
      archiveLocation.path,
      path.join(imageSavePath, "image.tar"),
      "expected full image path",
    );
    t.true(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image exists on disk",
    );

    archiveLocation.removeArchive();
    t.false(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image should not exists on disk",
    );
    t.notOk(
      fs.existsSync(imageSavePath),
      "tmp folder should not exist on disk",
    );
    t.ok(fs.existsSync(customPath), "custom path should exist on disk");
  });

  t.test("from remote registry without binary", async (t) => {
    const customPath = "./new_custom/image/save/path";
    const imageSavePath = path.join(customPath, uuidv4());
    const dockerPullSpy = sinon.spy(Docker.prototype, "pull");
    const subprocessStub = sinon.stub(subProcess, "execute");
    subprocessStub.throws();

    const archiveLocation = await imageInspector.getImageArchive(
      targetImage,
      imageSavePath,
    );
    t.teardown(() => {
      dockerPullSpy.restore();
      subprocessStub.restore();
      rmdirRecursive(customPath.split(path.sep));
    });

    t.true(
      dockerPullSpy.called,
      "image pulled from remote registry without binary",
    );
    t.equal(
      archiveLocation.path,
      path.join(imageSavePath, "image.tar"),
      "expected full image path",
    );
    t.true(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image exists on disk",
    );

    archiveLocation.removeArchive();
    t.false(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image should not exists on disk",
    );
    t.notOk(
      fs.existsSync(imageSavePath),
      "tmp folder should not exist on disk",
    );
    t.ok(fs.existsSync(customPath), "custom path should exist on disk");
  });

  t.test("from remote registry with authentication", async (t) => {
    const customPath = "./my_custom/image/save/path/auth";
    const imageSavePath = path.join(customPath, uuidv4());
    const dockerPullSpy: sinon.SinonSpy = sinon.spy(Docker.prototype, "pull");
    const subprocessStub = sinon.stub(subProcess, "execute");
    subprocessStub.throws();
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

    t.teardown(() => {
      dockerPullSpy.restore();
      subprocessStub.restore();
      rmdirRecursive(customPath.split(path.sep));
    });

    t.true(dockerPullSpy.calledOnce, "image pulled from remote registry");
    t.equal(
      archiveLocation.path,
      path.join(imageSavePath, "image.tar"),
      "expected full image path",
    );
    t.true(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image exists on disk",
    );

    archiveLocation.removeArchive();
    t.false(
      fs.existsSync(path.join(imageSavePath, "image.tar")),
      "image should not exists on disk",
    );
    t.notOk(
      fs.existsSync(imageSavePath),
      "tmp folder should not exist on disk",
    );
    t.ok(fs.existsSync(customPath), "custom path should exist on disk");
  });
});
