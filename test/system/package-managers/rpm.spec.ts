import { Docker } from "../../../lib/docker";
import { scan } from "../../../lib/index";
import { execute } from "../../../lib/sub-process";

describe("rpm package manager tests", () => {
  beforeAll(() => {
    // Mock Docker availability to force the OCI pull path.
    // Without this, local (Docker binary exists) uses "docker save" and returns file-path
    // imageLayers while CI (no Docker) uses registry pull and returns digest-based
    // imageLayers/rootFs (e.g., "sha256:<digest>"). This divergence makes snapshots
    // flaky across environments, so we standardize on OCI.
    jest.spyOn(Docker, "binaryExists").mockResolvedValue(false);
  });

  afterAll(async () => {
    // Restore the original implementation
    jest.restoreAllMocks();

    // Increased timeout for potentially slow image removal
    jest.setTimeout(60000);
    await execute("docker", [
      "image",
      "rm",
      "amazonlinux:2.0.20200722.0",
      "amazonlinux:2022.0.20220504.1",
      "registry.access.redhat.com/ubi9/ubi@sha256:c113f67e8e70940af28116d75e32f0aa4ffd3bf6fab30e970850475ab1de697f",
      "registry.access.redhat.com/ubi10-beta/ubi@sha256:4b4976d86eefeedab6884c9d2923206c6c3c2e2471206f97fd9d7aaaecbc04ac",
      "registry-1.docker.io/snykgoof/dockerhub-goof:centos-stream9",
      "registry-1.docker.io/snykgoof/dockerhub-goof:centos-stream10",
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
    // quay doesn't keep older shas, so the test would break every time
    // they pushed a new version. To mitigate this, we cloned an image
    // and pushed it to the snykgoof repo
    const image = "snykgoof/dockerhub-goof:centos-stream9";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });

  it("should correctly analyze a CentOS Stream 10 image", async () => {
    // quay doesn't keep older shas, so the test would break every time
    // they pushed a new version. To mitigate this, we cloned an image
    // and pushed it to the snykgoof repo
    const image = "snykgoof/dockerhub-goof:centos-stream10";
    const pluginResult = await scan({
      path: image,
      platform: "linux/amd64",
    });
    expect(pluginResult).toMatchSnapshot();
  });
});
