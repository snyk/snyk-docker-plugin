import { getJavaRuntimeReleaseAction } from "../../../lib/inputs/base-runtimes/static";
import { detectJavaRuntime } from "../../../lib/analyzer/base-runtimes";
import { ExtractedLayers } from "../../../lib/extractor/types";

const matches = getJavaRuntimeReleaseAction.filePathMatches!;

function makeLayer(filePath: string, content: string): ExtractedLayers {
  return { [filePath]: { "java-runtime-release": content } };
}

describe("getJavaRuntimeReleaseAction.filePathMatches", () => {
  describe("eclipse-temurin (/opt/java/openjdk/release)", () => {
    it("matches the exact path", () => {
      expect(matches("/opt/java/openjdk/release")).toBe(true);
    });

    it("does not match other files under /opt/java/openjdk/", () => {
      expect(matches("/opt/java/openjdk/conf/security")).toBe(false);
    });
  });

  describe("official Docker openjdk (/usr/local/openjdk-<version>/release)", () => {
    it("matches /usr/local/openjdk-11/release", () => {
      expect(matches("/usr/local/openjdk-11/release")).toBe(true);
    });

    it("matches /usr/local/openjdk-17/release", () => {
      expect(matches("/usr/local/openjdk-17/release")).toBe(true);
    });

    it("matches /usr/local/openjdk-21/release", () => {
      expect(matches("/usr/local/openjdk-21/release")).toBe(true);
    });

    it("does not match non-release files under /usr/local/openjdk-*", () => {
      expect(matches("/usr/local/openjdk-17/bin/java")).toBe(false);
    });
  });

  describe("any JVM under /usr/lib/jvm/ (Debian/Ubuntu openjdk, Azul Zulu, Amazon Corretto, Temurin, etc.)", () => {
    it("matches /usr/lib/jvm/java-17-openjdk-amd64/release", () => {
      expect(matches("/usr/lib/jvm/java-17-openjdk-amd64/release")).toBe(true);
    });

    it("matches /usr/lib/jvm/java-11-openjdk-arm64/release", () => {
      expect(matches("/usr/lib/jvm/java-11-openjdk-arm64/release")).toBe(true);
    });

    it("matches /usr/lib/jvm/java-21-openjdk-amd64/release", () => {
      expect(matches("/usr/lib/jvm/java-21-openjdk-amd64/release")).toBe(true);
    });

    it("matches Azul Zulu /usr/lib/jvm/zulu17/release", () => {
      expect(matches("/usr/lib/jvm/zulu17/release")).toBe(true);
    });

    it("matches Azul Zulu /usr/lib/jvm/zulu11/release", () => {
      expect(matches("/usr/lib/jvm/zulu11/release")).toBe(true);
    });

    it("matches Amazon Corretto /usr/lib/jvm/java-17-amazon-corretto/release", () => {
      expect(matches("/usr/lib/jvm/java-17-amazon-corretto/release")).toBe(
        true,
      );
    });

    it("matches Eclipse Temurin /usr/lib/jvm/temurin-17/release", () => {
      expect(matches("/usr/lib/jvm/temurin-17/release")).toBe(true);
    });

    it("does not match non-release files under /usr/lib/jvm/", () => {
      expect(matches("/usr/lib/jvm/java-17-openjdk-amd64/bin/java")).toBe(
        false,
      );
    });

    it("does not match non-release files under /usr/lib/jvm/zulu17/", () => {
      expect(matches("/usr/lib/jvm/zulu17/bin/java")).toBe(false);
    });
  });

  describe("Oracle JDK (/usr/java/<version>/release)", () => {
    it("matches /usr/java/jdk-17/release", () => {
      expect(matches("/usr/java/jdk-17/release")).toBe(true);
    });

    it("matches /usr/java/jdk-17.0.1/release", () => {
      expect(matches("/usr/java/jdk-17.0.1/release")).toBe(true);
    });

    it("matches /usr/java/latest/release", () => {
      expect(matches("/usr/java/latest/release")).toBe(true);
    });

    it("does not match non-release files under /usr/java/", () => {
      expect(matches("/usr/java/jdk-17/bin/java")).toBe(false);
    });
  });

  describe("non-matching paths", () => {
    it("does not match an arbitrary file named release", () => {
      expect(matches("/etc/release")).toBe(false);
    });

    it("does not match /opt/java/release (missing openjdk segment)", () => {
      expect(matches("/opt/java/release")).toBe(false);
    });

    it("does not match an empty string", () => {
      expect(matches("")).toBe(false);
    });
  });
});

describe("detectJavaRuntime — end-to-end per distribution", () => {
  it("detects eclipse-temurin via /opt/java/openjdk/release", () => {
    const content = `IMPLEMENTOR="Eclipse Adoptium"
IMPLEMENTOR_VERSION="Temurin-17.0.11+9"
JAVA_RUNTIME_VERSION="17.0.11+9"
JAVA_VERSION="17.0.11"
JAVA_VERSION_DATE="2024-04-16"
OS_ARCH="amd64"
OS_NAME="Linux"`;
    expect(
      detectJavaRuntime(makeLayer("/opt/java/openjdk/release", content)),
    ).toEqual({
      type: "java",
      version: "17.0.11",
    });
  });

  it("detects official Docker openjdk via /usr/local/openjdk-17/release", () => {
    // Official openjdk Docker images ship IMPLEMENTOR="N/A" for community builds
    const content = `IMPLEMENTOR="N/A"
IMPLEMENTOR_VERSION="17.0.9+9"
JAVA_RUNTIME_VERSION="17.0.9+9"
JAVA_VERSION="17.0.9"
JAVA_VERSION_DATE="2023-10-17"
OS_ARCH="amd64"
OS_NAME="Linux"`;
    expect(
      detectJavaRuntime(makeLayer("/usr/local/openjdk-17/release", content)),
    ).toEqual({ type: "java", version: "17.0.9" });
  });

  it("detects official Docker openjdk via /usr/local/openjdk-21/release", () => {
    const content = `IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="21.0.1"
JAVA_VERSION_DATE="2023-10-17"`;
    expect(
      detectJavaRuntime(makeLayer("/usr/local/openjdk-21/release", content)),
    ).toEqual({ type: "java", version: "21.0.1" });
  });

  it("detects Debian/Ubuntu default-jdk via /usr/lib/jvm/java-17-openjdk-amd64/release", () => {
    // Debian builds ship IMPLEMENTOR="Debian"
    const content = `IMPLEMENTOR="Debian"
IMPLEMENTOR_VERSION="17.0.9+9-1"
JAVA_RUNTIME_VERSION="17.0.9+9-1"
JAVA_VERSION="17.0.9"`;
    expect(
      detectJavaRuntime(
        makeLayer("/usr/lib/jvm/java-17-openjdk-amd64/release", content),
      ),
    ).toEqual({ type: "java", version: "17.0.9" });
  });

  it("detects Azul Zulu via /usr/lib/jvm/zulu17/release", () => {
    const content = `IMPLEMENTOR="Azul Systems, Inc."
IMPLEMENTOR_VERSION="Zulu17.48+15-CA"
JAVA_RUNTIME_VERSION="17.0.10+7"
JAVA_VERSION="17.0.10"
OS_ARCH="amd64"
OS_NAME="Linux"`;
    expect(
      detectJavaRuntime(makeLayer("/usr/lib/jvm/zulu17/release", content)),
    ).toEqual({ type: "java", version: "17.0.10" });
  });

  it("detects Oracle JDK via /usr/java/jdk-17.0.1/release", () => {
    const content = `IMPLEMENTOR="Oracle Corporation"
IMPLEMENTOR_VERSION="17.0.1+12"
JAVA_VERSION="17.0.1"
JAVA_VERSION_DATE="2021-10-19"`;
    expect(
      detectJavaRuntime(makeLayer("/usr/java/jdk-17.0.1/release", content)),
    ).toEqual({ type: "java", version: "17.0.1" });
  });

  it("returns null when no release file is present", () => {
    expect(detectJavaRuntime({})).toBeNull();
  });

  it("returns null when the release file has no JAVA_VERSION", () => {
    const content = `IMPLEMENTOR="Debian"\nOS_ARCH="amd64"`;
    expect(
      detectJavaRuntime(
        makeLayer("/usr/lib/jvm/java-17-openjdk-amd64/release", content),
      ),
    ).toBeNull();
  });
});
