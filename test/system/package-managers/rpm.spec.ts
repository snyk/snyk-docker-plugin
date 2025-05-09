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
      "registry.redhat.io/ubi9/ubi:latest",
      "registry.redhat.io/ubi10-beta/ubi:latest",
      "quay.io/centos/centos:stream9",
      "quay.io/centos/centos:stream10",
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
    const image = "registry.access.redhat.com/ubi9/ubi:9.5";
    try {
      await execute("docker", ["pull", image]);
    } catch (err) {
      console.warn(
        `Failed to pull ${image}, test might be unreliable if image is not present locally. Error: ${
          (err as Error).message
        }`,
      );
    }
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a RHEL 10 UBI Beta image", async () => {
    const image = "registry.access.redhat.com/ubi10-beta/ubi:10.0-beta";
    try {
      await execute("docker", ["pull", image]);
    } catch (err) {
      console.warn(
        `Failed to pull ${image}, test might be unreliable if image is not present locally. Error: ${
          (err as Error).message
        }`,
      );
    }
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a CentOS Stream 9 image", async () => {
    const image = "quay.io/centos/centos:stream9";
    try {
      await execute("docker", ["pull", image]);
    } catch (err) {
      console.warn(
        `Failed to pull ${image}, test might be unreliable if image is not present locally. Error: ${
          (err as Error).message
        }`,
      );
    }
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a CentOS Stream 9 image", async () => {
    const image = "quay.io/centos/centos:stream10";
    try {
      await execute("docker", ["pull", image]);
    } catch (err) {
      console.warn(
        `Failed to pull ${image}, test might be unreliable if image is not present locally. Error: ${
          (err as Error).message
        }`,
      );
    }
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });
});
