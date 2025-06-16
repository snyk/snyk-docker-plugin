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
      "quay.io/centos/centos@sha256:a4c1969e2563bb58ef1ace327b72f8cc3f1a7e760a0724ba02820420b66cbb46",
      "quay.io/centos/centos@sha256:7d0dcbf40012e732cb996a64ca997672028537172e527db893fcd59393d0a382",
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
      "quay.io/centos/centos@sha256:a4c1969e2563bb58ef1ace327b72f8cc3f1a7e760a0724ba02820420b66cbb46";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a CentOS Stream 10 image", async () => {
    const image =
      "quay.io/centos/centos@sha256:7d0dcbf40012e732cb996a64ca997672028537172e527db893fcd59393d0a382";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });
});
