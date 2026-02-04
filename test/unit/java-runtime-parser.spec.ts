import { parseJavaRuntimeRelease } from "../../lib/analyzer/java-runtime/parser";

describe("java runtime release parser", () => {
  it("parses a valid Java release file with JAVA_VERSION", () => {
    const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11"
IMAGE_TYPE="JRE"
MODULES="java.base java.logging java.xml"
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  it("parses a release file with single-quoted values", () => {
    const content = `
IMPLEMENTOR='Oracle Corporation'
JAVA_VERSION='21.0.1'
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "21.0.1" });
  });

  it("parses a release file with unquoted values", () => {
    const content = `
IMPLEMENTOR=Eclipse Adoptium
JAVA_VERSION=11.0.20
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "11.0.20" });
  });

  it("handles whitespace around keys and values", () => {
    const content = `
  IMPLEMENTOR  =  "Eclipse Adoptium"  
  JAVA_VERSION  =  "17.0.11"  
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  it("skips comment lines starting with #", () => {
    const content = `
# This is a comment
IMPLEMENTOR="Eclipse Adoptium"
# Another comment
JAVA_VERSION="17.0.11"
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  it("skips empty lines", () => {
    const content = `

IMPLEMENTOR="Eclipse Adoptium"

JAVA_VERSION="17.0.11"

`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  it("skips lines without equals sign", () => {
    const content = `
JAVA_VERSION
JAVA_VERSION="17.0.11"
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  it("returns null when content is empty", () => {
    const result = parseJavaRuntimeRelease("");
    expect(result).toBeNull();
  });

  it("returns null when content is only whitespace", () => {
    const result = parseJavaRuntimeRelease("   \n  \n   ");
    expect(result).toBeNull();
  });

  it("returns null when JAVA_VERSION is not present", () => {
    const content = `
IMPLEMENTOR="Eclipse Adoptium"
IMAGE_TYPE="JRE"
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toBeNull();
  });

  it("handles values containing equals signs", () => {
    const content = `
SOME_KEY="value=with=equals"
JAVA_VERSION="17.0.11"
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  it("parses a realistic Eclipse Temurin release file", () => {
    const content = `
IMPLEMENTOR="Eclipse Adoptium"
IMPLEMENTOR_VERSION="Temurin-17.0.11+9"
JAVA_RUNTIME_VERSION="17.0.11+9"
JAVA_VERSION="17.0.11"
JAVA_VERSION_DATE="2024-04-16"
LIBC="glibc"
MODULES="java.base java.compiler java.datatransfer java.desktop java.instrument java.logging java.management java.management.rmi java.naming java.net.http java.prefs java.rmi java.scripting java.se java.security.jgss java.security.sasl java.smartcardio java.sql java.sql.rowset java.transaction.xa java.xml java.xml.crypto jdk.accessibility jdk.attach jdk.charsets jdk.compiler jdk.crypto.cryptoki jdk.crypto.ec jdk.dynalink jdk.editpad jdk.hotspot.agent jdk.httpserver jdk.incubator.foreign jdk.incubator.vector jdk.internal.ed jdk.internal.jvmstat jdk.internal.le jdk.internal.opt jdk.internal.vm.ci jdk.internal.vm.compiler jdk.internal.vm.compiler.management jdk.jartool jdk.javadoc jdk.jcmd jdk.jconsole jdk.jdeps jdk.jdi jdk.jdwp.agent jdk.jfr jdk.jlink jdk.jpackage jdk.jshell jdk.jsobject jdk.jstatd jdk.localedata jdk.management jdk.management.agent jdk.management.jfr jdk.naming.dns jdk.naming.rmi jdk.net jdk.nio.mapmode jdk.random jdk.sctp jdk.security.auth jdk.security.jgss jdk.unsupported jdk.unsupported.desktop jdk.xml.dom jdk.zipfs"
OS_ARCH="x86_64"
OS_NAME="Linux"
SOURCE=".:git:13710926b798"
`;
    const result = parseJavaRuntimeRelease(content);
    expect(result).toEqual({ type: "java", version: "17.0.11" });
  });

  describe("returns null for malformed content", () => {
    it("returns null when JAVA_VERSION key has empty value", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION=""
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when JAVA_VERSION key has =", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="="
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when file contains only comments", () => {
      const content = `
# This is a comment
# Another comment
# JAVA_VERSION="17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when file contains only malformed lines without equals", () => {
      const content = `
IMPLEMENTOR Eclipse Adoptium
JAVA_VERSION 17.0.11
IMAGE_TYPE JRE
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when JAVA_VERSION key is misspelled", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVAVERSION="17.0.11"
JAVA_VER="17.0.11"
VERSION="17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when JAVA_VERSION is lowercase", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
java_version="17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when file has other version keys but not JAVA_VERSION", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_RUNTIME_VERSION="17.0.11+9"
IMPLEMENTOR_VERSION="Temurin-17.0.11+9"
FULL_VERSION="17.0.11+9"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when content is binary/garbage data", () => {
      const content = "\x00\x01\x02\x03\x04\x05";
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when JAVA_VERSION value is only whitespace", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="   "
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null for completely unrelated file content", () => {
      const content = `
{
  "name": "some-package",
  "version": "1.0.0"
}
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null for XML-like content", () => {
      const content = `
<?xml version="1.0" encoding="UTF-8"?>
<java>
  <version>17.0.11</version>
</java>
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when only key exists without value", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION=
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when multiple JAVA_VERSION keys are present", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11"
JAVA_VERSION="21.0.1"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when multiple JAVA_VERSION keys have same value", () => {
      const content = `
JAVA_VERSION="17.0.11"
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when multiple JAVA_VERSION keys with different quotes", () => {
      const content = `
JAVA_VERSION="17.0.11"
JAVA_VERSION='17.0.11'
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });
  });

  describe("valid version formats", () => {
    it("parses valid version with dots only", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "17.0.11" });
    });

    it("parses valid simple major version", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="21"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "21" });
    });

    it("parses valid version with underscore (old Java format)", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="1.8.0_392"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "1.8.0_392" });
    });

    it("parses valid version with plus sign (build metadata)", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11+9"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "17.0.11+9" });
    });

    it("parses valid version with underscore and plus", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="1.8.0_392+8"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "1.8.0_392+8" });
    });

    it("parses early access version with -ea suffix", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="21-ea"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "21-ea" });
    });

    it("parses early access version with -ea and build number", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="21-ea+35"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "21-ea+35" });
    });

    it("parses beta version", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="1.3.1-beta"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "1.3.1-beta" });
    });

    it("parses release candidate version", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="17-rc"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "17-rc" });
    });

    it("parses legacy build format with -b suffix", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="1.8.0_392-b08"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "1.8.0_392-b08" });
    });

    it("parses version with internal designation", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="17.0.11-internal"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "17.0.11-internal" });
    });

    it("parses version with multiple hyphens", () => {
      const content = `
IMPLEMENTOR="Oracle Corporation"
JAVA_VERSION="21-ea-preview"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toEqual({ type: "java", version: "21-ea-preview" });
    });
  });

  describe("invalid version formats", () => {
    it("returns null when version is purely alphabetic (no leading number)", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="seventeen"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version starts with a letter", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="v17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains @", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11@latest"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains # within quotes", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11#build"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains $", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="$17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains parentheses", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11(LTS)"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains spaces", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17 0 11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version starts with a dot", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION=".17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version ends with a dot", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11."
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version has consecutive dots", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17..0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains slash", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17/0/11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains backslash", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17\\0\\11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains colon", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17:0:11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version starts with hyphen", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="-17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version starts with plus", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="+17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version starts with underscore", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="_17.0.11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains asterisk", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.*"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains exclamation mark", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17.0.11!"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains ampersand", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17&0&11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });

    it("returns null when version contains percent", () => {
      const content = `
IMPLEMENTOR="Eclipse Adoptium"
JAVA_VERSION="17%0%11"
`;
      const result = parseJavaRuntimeRelease(content);
      expect(result).toBeNull();
    });
  });

  describe(" handles malformed input safely", () => {
    describe("input size limits", () => {
      it("returns null for extremely large content", () => {
        const largeContent = "A".repeat(10 * 1024 * 1024);
        const result = parseJavaRuntimeRelease(largeContent);
        expect(result).toBeNull();
      });

      it("returns null for content with too many lines ", () => {
        const manyLines = Array(1_000_000).fill("KEY=value").join("\n");
        const result = parseJavaRuntimeRelease(manyLines);
        expect(result).toBeNull();
      });

      it("returns null when JAVA_VERSION value itself is invalid (malformed)", () => {
        const invalidVersion =
          "1.2.3.invalid.version.with.too.many.dots.and.invalid.chars!@#";
        const content = `JAVA_VERSION="${invalidVersion}"`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toBeNull(); // Invalid because version doesn't match pattern
      });

      it("extracts version correctly even with long comments", () => {
        const longComment =
          " # This is a very long comment: " + "comment ".repeat(10000);
        const content = `JAVA_VERSION=17.0.11${longComment}`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toEqual({ type: "java", version: "17.0.11" });
      });
    });

    describe("edge cases with special content", () => {
      it("handles content with only null bytes", () => {
        const content = "\x00\x00\x00\x00";
        const result = parseJavaRuntimeRelease(content);
        expect(result).toBeNull();
      });

      it("handles content with mixed null bytes and valid data", () => {
        const content = `JAVA_VERSION="17.0.11"\x00\x00\x00`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toEqual({ type: "java", version: "17.0.11" });
      });

      it("handles content with various line endings", () => {
        const content = `IMPLEMENTOR="Eclipse"\r\nJAVA_VERSION="17.0.11"\r\n`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toEqual({ type: "java", version: "17.0.11" });
      });

      it("handles content with mixed line endings", () => {
        const content = `IMPLEMENTOR="Eclipse"\r\nJAVA_VERSION="17.0.11"\nOTHER="value"\r`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toEqual({ type: "java", version: "17.0.11" });
      });

      it("handles extremely deep nesting in value (no stack overflow)", () => {
        const deepNested = "{".repeat(10000) + "}".repeat(10000);
        const content = `JAVA_VERSION="${deepNested}"`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toBeNull();
      });

      it("handles unicode characters in version", () => {
        const content = `JAVA_VERSION="17.0.11™"`;
        const result = parseJavaRuntimeRelease(content);
        expect(result).toBeNull();
      });
    });
  });
});
