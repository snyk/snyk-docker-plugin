import { ExtractedLayers } from "../../../../lib/extractor/types";
import {
  getRedHatRepositoriesContentAction,
  getRedHatRepositoriesFromExtractedLayers,
} from "../../../../lib/inputs/redHat/static";
import { getObjFromFixture } from "../../../util";

describe("getRedHatRepositoriesFromExtractedLayers", () => {
  it("returns unique set of repositories from rhel7 image", () => {
    const extractedLayers = getObjFromFixture(
      "extracted-layers/rhel7-with-content-manifests.json",
    );

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toMatchObject([
      "rhel-7-server-ose-3.11-rpms",
      "rhel-server-rhscl-7-rpms",
      "rhel-7-server-rpms",
    ]);
  });

  it("returns unique set of repositories from ubi8 image", () => {
    const extractedLayers = getObjFromFixture(
      "extracted-layers/ubi8-with-content-manifests.json",
    );

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toMatchObject([
      "rhel-8-for-x86_64-baseos-rpms",
      "rhel-8-for-x86_64-appstream-rpms",
      "rhel-8-for-x86_64-baseos-beta-rpms",
      "rhel-8-for-x86_64-appstream-beta-rpms",
      "rhel-8-for-x86_64-baseos-htb-rpms",
      "rhel-8-for-x86_64-appstream-htb-rpms",
    ]);
  });

  it("returns empty array when no RedHat content manifests are found", () => {
    const extractedLayers: ExtractedLayers = {
      "/some/other/path/file.txt": {
        "some-action": "content",
      },
      "/usr/lib/file.json": {
        "another-action": "test",
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual([]);
  });

  it("handles missing contentManifest gracefully", () => {
    const extractedLayers: ExtractedLayers = {
      "/root/buildinfo/content_manifests/test.json": {
        "redhat-content-manifests": undefined as any,
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual([]);
  });

  it("handles contentManifest without content_sets", () => {
    const extractedLayers: ExtractedLayers = {
      "/root/buildinfo/content_manifests/test.json": {
        "redhat-content-manifests": {
          metadata: { version: "1.0" },
          // content_sets is missing
        } as any,
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual([]);
  });

  it("handles contentManifest with empty content_sets", () => {
    const extractedLayers: ExtractedLayers = {
      "/root/buildinfo/content_manifests/test.json": {
        "redhat-content-manifests": {
          content_sets: [],
        } as any,
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual([]);
  });

  it("deduplicates repositories across multiple manifests", () => {
    const extractedLayers: ExtractedLayers = {
      "/root/buildinfo/content_manifests/manifest1.json": {
        "redhat-content-manifests": {
          content_sets: ["repo-a", "repo-b", "repo-c"],
        } as any,
      },
      "/root/buildinfo/content_manifests/manifest2.json": {
        "redhat-content-manifests": {
          content_sets: ["repo-b", "repo-c", "repo-d"],
        } as any,
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual(["repo-a", "repo-b", "repo-c", "repo-d"]);
  });

  it("handles mixed valid and invalid manifests", () => {
    const extractedLayers: ExtractedLayers = {
      "/root/buildinfo/content_manifests/valid.json": {
        "redhat-content-manifests": {
          content_sets: ["valid-repo-1", "valid-repo-2"],
        } as any,
      },
      "/root/buildinfo/content_manifests/missing-content-sets.json": {
        "redhat-content-manifests": {
          metadata: { version: "1.0" },
        } as any,
      },
      "/root/buildinfo/content_manifests/null-manifest.json": {
        "redhat-content-manifests": null as any,
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual(["valid-repo-1", "valid-repo-2"]);
  });

  it("handles contentManifest with null content_sets", () => {
    const extractedLayers: ExtractedLayers = {
      "/root/buildinfo/content_manifests/test.json": {
        "redhat-content-manifests": {
          content_sets: null,
        } as any,
      },
    };

    const repositories =
      getRedHatRepositoriesFromExtractedLayers(extractedLayers);

    expect(repositories).toEqual([]);
  });
});

describe("getRedHatRepositoriesContentAction", () => {
  it("has correct action configuration", () => {
    expect(getRedHatRepositoriesContentAction.actionName).toBe(
      "redhat-content-manifests",
    );
    expect(typeof getRedHatRepositoriesContentAction.filePathMatches).toBe(
      "function",
    );
    expect(typeof getRedHatRepositoriesContentAction.callback).toBe("function");
  });

  it("filePathMatches correctly identifies RedHat content manifest paths", () => {
    const validPaths = [
      "/root/buildinfo/content_manifests/test.json",
      "/root/buildinfo/content_manifests/rhel7.json",
      "/root/buildinfo/content_manifests/nested/path/manifest.json",
    ];

    const invalidPaths = [
      "/usr/lib/content_manifests/test.json",
      "/root/other/content_manifests/test.json",
      "/content_manifests/test.json",
      "/root/buildinfo/other/test.json",
    ];

    validPaths.forEach((path) => {
      expect(getRedHatRepositoriesContentAction.filePathMatches(path)).toBe(
        true,
      );
    });

    invalidPaths.forEach((path) => {
      expect(getRedHatRepositoriesContentAction.filePathMatches(path)).toBe(
        false,
      );
    });
  });
});
