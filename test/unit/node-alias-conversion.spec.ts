import { convertPkgTreeToDepTree, convertLabels } from "../../lib/analyzer/applications/node";

describe("Node.js Alias Conversion", () => {
  describe("convertLabels", () => {
    it("should convert string labels correctly", () => {
      const labels = {
        scope: "dev",
        pruned: "cyclic",
        someLabel: "someValue",
      };

      const result = convertLabels(labels);

      expect(result).toEqual({
        scope: "dev",
        pruned: "cyclic",
        someLabel: "someValue",
      });
    });

    it("should convert Alias objects to strings", () => {
      const labels = {
        scope: "prod",
        alias: {
          aliasName: "lodash-legacy",
          aliasTargetDepName: "lodash",
          semver: "^3.10.1",
          version: "3.10.1",
        },
      };

      const result = convertLabels(labels);

      expect(result).toEqual({
        scope: "prod",
        alias: "lodash-legacy@3.10.1",
      });
    });

    it("should handle mixed string and Alias labels", () => {
      const labels = {
        scope: "prod",
        pruned: "true",
        alias: {
          aliasName: "react-old",
          aliasTargetDepName: "react",
          semver: "^16.14.0",
          version: "16.14.0",
        },
        customLabel: "custom-value",
      };

      const result = convertLabels(labels);

      expect(result).toEqual({
        scope: "prod",
        pruned: "true",
        alias: "react-old@16.14.0",
        customLabel: "custom-value",
      });
    });

    it("should handle undefined and null values", () => {
      const labels = {
        scope: "dev",
        undefinedValue: undefined,
        nullValue: null,
        validValue: "valid",
      };

      const result = convertLabels(labels);

      expect(result).toEqual({
        scope: "dev",
        validValue: "valid",
      });
    });

    it("should handle empty labels", () => {
      const result = convertLabels(undefined);
      expect(result).toBeUndefined();

      const resultEmpty = convertLabels({});
      expect(resultEmpty).toEqual({});
    });
  });

  describe("convertPkgTreeToDepTree", () => {
    it("should convert a PkgTree with alias labels to DepTree", () => {
      const pkgTree = {
        name: "my-app",
        version: "1.0.0",
        type: "npm",
        dependencies: {
          "lodash-legacy": {
            name: "lodash-legacy",
            version: "3.10.1",
            labels: {
              alias: {
                aliasName: "lodash-legacy",
                aliasTargetDepName: "lodash",
                semver: "^3.10.1",
                version: "3.10.1",
              },
            },
          },
          "regular-dep": {
            name: "regular-dep",
            version: "2.0.0",
            labels: {
              scope: "prod",
            },
          },
        },
        labels: {
          scope: "prod",
        },
      };

      const result = convertPkgTreeToDepTree(pkgTree);

      expect(result.name).toBe("my-app");
      expect(result.version).toBe("1.0.0");
      expect(result.type).toBe("npm");
      expect(result.labels).toEqual({ scope: "prod" });
      expect(result.dependencies).toBeDefined();
      expect(result.dependencies!["lodash-legacy"]).toBeDefined();
      expect(result.dependencies!["lodash-legacy"].labels).toEqual({
        alias: "lodash-legacy@3.10.1",
      });
      expect(result.dependencies!["regular-dep"].labels).toEqual({
        scope: "prod",
      });
    });
  });
});






