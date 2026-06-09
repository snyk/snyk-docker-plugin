import { DepGraph } from "@snyk/dep-graph";

import * as plugin from "../../lib";
import { getFixture } from "../util";

describe("windows scanning", () => {
  it("can scan docker-archive image type", async () => {
    const fixturePath = getFixture("docker-archives/docker-save/nginx.tar");
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|nginx.tar");
    expect(depGraph.rootPkg.version).toBeUndefined();

    const imageId: string = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;
    expect(imageId).toEqual(
      "sha256:5a3221f0137beb960c34b9cf4455424b6210160fd618c5e79401a07d6e5a2ced",
    );
    expect(pluginResult.scanResults[0].identity.type).toEqual("deb");
    expect(
      depGraph.getDepPkgs().find((dep) => dep.name === "adduser"),
    ).toBeDefined();

    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers).toEqual([
      "sha256:1c95c77433e8d7bf0f519c9d8c9ca967e2603f0defbf379130d9a841cca2e28e",
      "sha256:002a63507c1caa5cc0e1af10e5b888f6ba20d06275e989a452581d789a48948e",
      "sha256:12fdf55172df870a613a79c4757006c5b28e66a8621c3e26916678378568f078",
    ]);
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "linux/amd64",
    );
  });

  it("can scan oci-archive image type", async () => {
    const fixturePath = getFixture("oci-archives/alpine-3.12.0.tar");
    const imageNameAndTag = `oci-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|alpine-3.12.0.tar");
    expect(depGraph.rootPkg.version).toBeUndefined();
    const imageId: string = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageId",
    )!.data;
    expect(imageId).toEqual(
      "sha256:0f5f445df8ccbd8a062ad3d02d459e8549d9998c62a5b7cbf77baf68aa73bf5b",
    );
    expect(pluginResult.scanResults[0].identity.type).toEqual("apk");
    expect(
      depGraph
        .getDepPkgs()
        .find((dep) => dep.name === "alpine-keys/alpine-keys"),
    ).toBeDefined();
    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers).toEqual([
      "sha256:50644c29ef5a27c9a40c393a73ece2479de78325cae7d762ef3cdc19bf42dd0a",
    ]);
  });

  it("can static scan for Identifier type image (nginx:1.19.11)", async () => {
    const imageNameAndTag = "nginx:1.19.11";

    await expect(() =>
      plugin.scan({
        path: imageNameAndTag,
      }),
    ).rejects.toEqual(
      new Error("The image does not exist for the current platform"),
    );
  });

  it("can static scan for Identifier type image (python:3.9.0)", async () => {
    const imageNameAndTag =
      "python@sha256:1f92d35b567363820d0f2f37c7ccf2c1543e2d852cea01edb027039e6aef25e6";

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
      "exclude-app-vulns": true,
    });

    const depGraph: DepGraph = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "depGraph",
    )!.data;
    expect(depGraph.rootPkg.name).toEqual("docker-image|python");
    expect(depGraph.rootPkg.version).toBeUndefined();
    expect(pluginResult.scanResults[0].identity.type).toEqual("linux");
    const imageLayers: string[] = pluginResult.scanResults[0].facts.find(
      (fact) => fact.type === "imageLayers",
    )!.data;
    expect(imageLayers.length).toBeGreaterThan(0);
    expect(
      imageLayers.every((layer) => layer.startsWith("sha256:")),
    ).toBeTruthy();
    expect(pluginResult.scanResults[0].identity.args?.platform).toEqual(
      "windows/amd64",
    );
  }, 900000);

  it("can scan docker-archive image type with go binaries", async () => {
    const fixturePath = getFixture(
      "docker-archives/docker-save/go-binaries.tar",
    );
    const imageNameAndTag = `docker-archive:${fixturePath}`;

    const pluginResult = await plugin.scan({
      path: imageNameAndTag,
      "app-vulns": true,
    });

    const esbuildResultFound = pluginResult.scanResults.find(
      (r) => r.identity.targetFile && r.identity.targetFile.includes("esbuild"),
    );

    expect(esbuildResultFound).toBeTruthy();
  });
});
