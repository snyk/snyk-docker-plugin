import { BaseRuntime } from "../../facts";

const VALID_VERSION_PATTERN =
  /^(?!.*\.\.)[0-9]+(?:[._+a-zA-Z0-9-]*[a-zA-Z0-9])?$/;

function isValidJavaVersion(version: string): boolean {
  if (!version || version.length === 0) {
    return false;
  }
  return VALID_VERSION_PATTERN.test(version);
}

export function parseJavaRuntimeRelease(content: string): BaseRuntime | null {
  if (!content || content.trim().length === 0) {
    return null;
  }
  try {
    const regex = /^\s*JAVA_VERSION\s*=\s*(?:(["'])(.*?)\1|([^#\r\n]+))/gm;
    const matches = [...content.matchAll(regex)];

    if (matches.length !== 1) {
      return null;
    }
    const version = (matches[0][2] || matches[0][3] || "").trim();

    if (!isValidJavaVersion(version)) {
      return null;
    }
    return { type: "java", version };
  } catch (error) {
    return null;
  }
}
