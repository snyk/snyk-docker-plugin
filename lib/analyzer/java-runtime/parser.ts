import { JavaRuntimeMetadata } from "../../facts";

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
export function parseJavaRuntimeRelease(
  content: string,
): JavaRuntimeMetadata | null {
  if (!content || content.trim().length === 0) {
    return null;
  }
  try {
    const lines = content.split("\n");
    const properties: Record<string, string> = {};

    for (const line of lines) {
      const trimmedLine = line.trim();
      if (!trimmedLine || trimmedLine.startsWith("#")) {
        continue;
      }
      const equalsIndex = trimmedLine.indexOf("=");
      if (equalsIndex === -1) {
        continue;
      }
      // extracts the key and value, and removes whitespace surrounding each key and value
      const key = trimmedLine.substring(0, equalsIndex).trim();
      let value = trimmedLine.substring(equalsIndex + 1).trim();
      
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.substring(1, value.length - 1);
      }

      properties[key] = value;
    }
    return properties.JAVA_VERSION
      ? { javaVersion: properties.JAVA_VERSION }
      : null;
  } catch (error) {
    return null;
  }
}
