import {
  getContentAsString,
  mergeImageLabels,
} from "../../../lib/extractor";
import { ExtractAction, ExtractedLayers } from "../../../lib/extractor/types";

describe("index", () => {
  test("getContentAsString() does matches when a pattern is used in the extract action", async () => {
    const extractAction: ExtractAction = {
      actionName: "match-any-node",
      filePathMatches: (filePath) => filePath.endsWith("node"),
    };
    const extractedLayers: ExtractedLayers = {
      "/var/lib/node": {
        "match-any-node": "Hello, world!",
      },
    };
    const result = getContentAsString(extractedLayers, extractAction);

    //  extracted string matches
    expect(result).toEqual("Hello, world!");
  });
});

describe("mergeImageLabels", () => {
  it("returns undefined when both annotations and configLabels are undefined", () => {
    expect(mergeImageLabels(undefined, undefined)).toBeUndefined();
  });

  it("returns configLabels alone when annotations are undefined", () => {
    const configLabels = { maintainer: "team@example.com", version: "1.0" };
    const result = mergeImageLabels(undefined, configLabels);
    expect(result).toEqual({ maintainer: "team@example.com", version: "1.0" });
  });

  it("returns an empty object when annotations are undefined and configLabels is an empty object", () => {
    const result = mergeImageLabels(undefined, {});
    expect(result).toEqual({});
  });

  it("returns annotations alone when configLabels are undefined", () => {
    const annotations = {
      "org.opencontainers.image.source": "https://github.com/example/repo",
      "org.opencontainers.image.revision": "abc123",
    };
    const result = mergeImageLabels(annotations, undefined);
    expect(result).toEqual({
      "org.opencontainers.image.source": "https://github.com/example/repo",
      "org.opencontainers.image.revision": "abc123",
    });
  });

  it("merges annotations and configLabels into a single map", () => {
    const annotations = {
      "org.opencontainers.image.source": "https://github.com/example/repo",
      team: "platform",
    };
    const configLabels = { maintainer: "team@example.com" };
    const result = mergeImageLabels(annotations, configLabels);
    expect(result).toEqual({
      "org.opencontainers.image.source": "https://github.com/example/repo",
      team: "platform",
      maintainer: "team@example.com",
    });
  });

  it("configLabels take precedence over annotations on key collision", () => {
    const annotations = { team: "from-annotation", extra: "only-in-annotation" };
    const configLabels = { team: "from-config-label", owner: "alice" };
    const result = mergeImageLabels(annotations, configLabels);
    expect(result).toEqual({
      team: "from-config-label",
      extra: "only-in-annotation",
      owner: "alice",
    });
  });

  it("preserves OCI annotation key names verbatim without sanitization", () => {
    const annotations = {
      "org.opencontainers.image.source": "https://example.com",
      "org.opencontainers.image.created": "2024-01-01T00:00:00Z",
      "com.example.custom-key": "value",
    };
    const result = mergeImageLabels(annotations, undefined);
    // Use direct property access because toHaveProperty() treats dots as
    // property-path separators, which would not match flat key names.
    expect(result!["org.opencontainers.image.source"]).toBe(
      "https://example.com",
    );
    expect(result!["org.opencontainers.image.created"]).toBe(
      "2024-01-01T00:00:00Z",
    );
    expect(result!["com.example.custom-key"]).toBe("value");
  });
});
