// tslint:disable:max-line-length
// tslint:disable:object-literal-key-quotes

import * as fs from "fs";
import * as path from "path";
import * as sinon from "sinon";
import { test } from "tap";

import * as imageInspector from "../../../lib/analyzer/image-inspector";
import { ArchiveResult } from "../../../lib/analyzer/types";
import { Docker } from "../../../lib/docker";
import * as subProcess from "../../../lib/sub-process";

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
    const dockerPullSpy = sinon.spy(Docker.prototype, "pull");

    const loadImage = path.join(
      __dirname,
      "../../fixtures/docker-archives",
      "docker-save/hello-world.tar",
    );
    await subProcess.execute("docker", ["load", "--input", loadImage]);
    const archiveLocation = await imageInspector.getImageArchive(targetImage);

    t.teardown(async () => {
      dockerPullSpy.restore();
      archiveLocation.removeArchive();
      await subProcess.execute("docker", ["image", "rm", targetImage]);
    });

    t.true(fs.existsSync(archiveLocation.path), "file exists on disk");
    t.false(dockerPullSpy.called, "image was not pulled from remote registry");
  });

  t.test("from remote registry with binary", async (t) => {
    const dockerPullSpy = sinon.spy(Docker.prototype, "pull");

    const archiveLocation: ArchiveResult = await imageInspector.getImageArchive(
      targetImage,
    );
    t.teardown(async () => {
      dockerPullSpy.restore();
      archiveLocation.removeArchive();
      await subProcess.execute("docker", ["image", "rm", targetImage]);
    });

    t.true(
      dockerPullSpy.notCalled,
      "image pulled from remote registry with binary",
    );
    t.true(fs.existsSync(archiveLocation.path), "image exists on disks");
  });

  t.test("from remote registry without binary", async (t) => {
    const dockerPullSpy = sinon.spy(Docker.prototype, "pull");
    const subprocessStub = sinon.stub(subProcess, "execute");
    subprocessStub.throws();

    const archiveLocation = await imageInspector.getImageArchive(targetImage);
    t.teardown(() => {
      dockerPullSpy.restore();
      subprocessStub.restore();
      archiveLocation.removeArchive();
    });

    t.true(
      dockerPullSpy.called,
      "image pulled from remote registry without binary",
    );
    t.true(fs.existsSync(archiveLocation.path), "image exists on disks");
  });

  t.test("from remote registry with authentication", async (t) => {
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
      username,
      password,
    );

    t.teardown(() => {
      dockerPullSpy.restore();
      subprocessStub.restore();
      archiveLocation.removeArchive();
    });

    t.true(dockerPullSpy.calledOnce, "image pulled from remote registry");
    t.true(fs.existsSync(archiveLocation.path), "image exists on disks");
  });
});
