import { BaseRuntime } from "../../facts";

const MAX_CONTENT_LENGTH = 10 * 1024;
const MAX_LINE_COUNT = 100;
const MAX_VERSION_LENGTH = 50;

// Valid Java version pattern:
// - must start with a digit
// - can contain: digits, dots, underscores, plus signs, hyphens, and letters (for -ea, -beta, -rc, etc.)
// - cannot have consecutive dots
// - cannot start or end with a dot
const VALID_VERSION_PATTERN = /^[0-9]+([._+a-zA-Z0-9-]*[a-zA-Z0-9])?$/;

function isValidJavaVersion(version: string): boolean {
  if (!version || version.length === 0 || version.length > MAX_VERSION_LENGTH) {
    return false;
  }
  if (version.includes("..")) {
    return false;
  }
  if (version.startsWith(".") || version.endsWith(".")) {
    return false;
  }
  return VALID_VERSION_PATTERN.test(version);
}

/**
 * Parses the Java runtime release file content into structured metadata.
 *
 * The release file format is key="value" pairs, one per line:
 * Example:
 * IMPLEMENTOR="Eclipse Adoptium"
 * JAVA_VERSION="17.0.11"
 * IMAGE_TYPE="JRE"
 * MODULES="java.base java.logging java.xml ..."
 * ... Other fields ...
 */
export function parseJavaRuntimeRelease(content: string): BaseRuntime | null {
  if (!content || content.trim().length === 0) {
    return null;
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return null;
  }
  try {
    const lines = content.split("\n");

    if (lines.length > MAX_LINE_COUNT) {
      return null;
    }
    let javaVersion: string | null = null;
    let javaVersionCount = 0;

    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine || trimmedLine.startsWith("#")) {
        continue;
      }
      const equalsIndex = trimmedLine.indexOf("=");
      if (equalsIndex === -1) {
        continue;
      }
      const key = trimmedLine.substring(0, equalsIndex).trim();
      if (key !== "JAVA_VERSION") {
        continue;
      }
      javaVersionCount++;
      if (javaVersionCount > 1) {
        return null;
      }
      let value = trimmedLine.substring(equalsIndex + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.substring(1, value.length - 1);
      }
      value = value.trim();

      if (!isValidJavaVersion(value)) {
        return null;
      }
      javaVersion = value;
    }
    return javaVersion ? { type: "java", version: javaVersion } : null;
  } catch (error) {
    return null;
  }
}
