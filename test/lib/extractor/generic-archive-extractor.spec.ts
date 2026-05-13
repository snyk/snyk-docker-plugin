import {
  createExtractArchive,
  createGetImageIdFromManifest,
  dockerArchiveConfig,
  getManifestLayers,
  kanikoArchiveConfig,
} from "../../../lib/extractor/generic-archive-extractor";
import {
  DockerArchiveManifest,
  KanikoArchiveManifest,
} from "../../../lib/extractor/types";
import { getFixture } from "../../util/index";

describe("generic archive extractor", () => {
  describe("createExtractArchive", () => {
    describe("with docker archive config", () => {
      const extractArchive = createExtractArchive(dockerArchiveConfig);

      it("extracts layers and manifest from a docker archive", async () => {
        const fixture = getFixture(
          "docker-archives/docker-save/nginx-with-buildinfo.tar",
        );
        const result = await extractArchive(fixture, [], {});
        expect(result.layers).toBeDefined();
        expect(result.manifest).toBeDefined();
        expect(result.imageConfig).toBeDefined();
      });
    });

    describe("with kaniko archive config", () => {
      const extractArchive = createExtractArchive(kanikoArchiveConfig);

      it("extracts layers and manifest from a kaniko archive", async () => {
        const fixture = getFixture("kaniko-archives/kaniko-busybox.tar");
        const result = await extractArchive(fixture, [], {});
        expect(result.layers).toBeDefined();
        expect(result.manifest).toBeDefined();
        expect(result.imageConfig).toBeDefined();
      });
    });

    it("rejects with an error when given a non-existent file", async () => {
      const extractArchive = createExtractArchive(dockerArchiveConfig);
      await expect(
        extractArchive("non-existent.tar", [], {}),
      ).rejects.toThrow();
    });
  });

  describe("createGetImageIdFromManifest", () => {
    describe("with docker archive config (strips .json extension)", () => {
      const getImageIdFromManifest =
        createGetImageIdFromManifest(dockerArchiveConfig);

      it("strips .json and returns imageId with sha256: prefix when prefix is present", () => {
        const manifest: DockerArchiveManifest = {
          Config:
            "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538.json",
          RepoTags: [],
          Layers: [],
        };
        expect(getImageIdFromManifest(manifest)).toEqual(
          "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
        );
      });

      it("strips .json and prepends sha256: when prefix is absent", () => {
        const manifest: DockerArchiveManifest = {
          Config:
            "2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538.json",
          RepoTags: [],
          Layers: [],
        };
        expect(getImageIdFromManifest(manifest)).toEqual(
          "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
        );
      });
    });

    describe("with kaniko archive config (uses Config value directly)", () => {
      const getImageIdFromManifest =
        createGetImageIdFromManifest(kanikoArchiveConfig);

      it("returns imageId as-is when sha256: prefix is present", () => {
        const manifest: KanikoArchiveManifest = {
          Config:
            "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
          RepoTags: [],
          Layers: [],
        };
        expect(getImageIdFromManifest(manifest)).toEqual(
          "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
        );
      });

      it("prepends sha256: when prefix is absent", () => {
        const manifest: KanikoArchiveManifest = {
          Config:
            "2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
          RepoTags: [],
          Layers: [],
        };
        expect(getImageIdFromManifest(manifest)).toEqual(
          "sha256:2565821efb5e5b95b36541004fa0287732a11f97a4a0ff807cc065746f82538",
        );
      });
    });

    it("throws when Config is missing", () => {
      const getImageIdFromManifest =
        createGetImageIdFromManifest(dockerArchiveConfig);
      const manifest = { Config: undefined, RepoTags: [], Layers: [] } as any;
      expect(() => getImageIdFromManifest(manifest)).toThrow(
        "Failed to extract image ID from archive manifest",
      );
    });
  });

  describe("getManifestLayers", () => {
    it("normalizes layer paths", () => {
      const manifest: DockerArchiveManifest = {
        Config: "abc.json",
        RepoTags: [],
        Layers: ["a/b/../c/layer.tar", "d/layer.tar"],
      };
      const result = getManifestLayers(manifest);
      expect(result).toEqual(["a/c/layer.tar", "d/layer.tar"]);
    });
  });
});
