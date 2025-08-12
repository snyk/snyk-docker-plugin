import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("rpm package manager tests", () => {
  afterAll(async () => {
    // Increased timeout for potentially slow image removal
    jest.setTimeout(60000);
    await execute("docker", [
      "image",
      "rm",
      "amazonlinux:2.0.20200722.0",
      "amazonlinux:2022.0.20220504.1",
      "registry.access.redhat.com/ubi9/ubi@sha256:c113f67e8e70940af28116d75e32f0aa4ffd3bf6fab30e970850475ab1de697f",
      "registry.access.redhat.com/ubi10-beta/ubi@sha256:4b4976d86eefeedab6884c9d2923206c6c3c2e2471206f97fd9d7aaaecbc04ac",
      "quay.io/centos/centos@sha256:45650b7974762418b66987d67c063aee0d2fab0ac8fade2db9807b3ec4bbd1af",
      "quay.io/centos/centos@sha256:683927bd29076a14ff8f74419da9042a5e1d308af048244108247a26365bd1e3",
    ]).catch(() => {
      console.error(`tests teardown failed to remove docker image`);
    });
  });

  it("should correctly analyze an rpm image", async () => {
    const image = "amazonlinux:2.0.20200722.0";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze an rpm image with sqlite DB", async () => {
    const image = "amazonlinux:2022.0.20220504.1";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a RHEL 9 UBI image", async () => {
    const image =
      "registry.access.redhat.com/ubi9/ubi@sha256:c113f67e8e70940af28116d75e32f0aa4ffd3bf6fab30e970850475ab1de697f";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a RHEL 10 UBI Beta image", async () => {
    const image =
      "registry.access.redhat.com/ubi10-beta/ubi@sha256:4b4976d86eefeedab6884c9d2923206c6c3c2e2471206f97fd9d7aaaecbc04ac";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a CentOS Stream 9 image", async () => {
    const image =
      "quay.io/centos/centos@sha256:45650b7974762418b66987d67c063aee0d2fab0ac8fade2db9807b3ec4bbd1af";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a CentOS Stream 10 image", async () => {
    const image =
      "quay.io/centos/centos@sha256:683927bd29076a14ff8f74419da9042a5e1d308af048244108247a26365bd1e3";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });
});
