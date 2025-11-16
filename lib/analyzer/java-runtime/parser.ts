import { JavaRuntimeMetadata } from "../../facts";

/**
 * Parses the Java runtime release file content into structured metadata.
 * 
 * The release file format is key="value" pairs, one per line:
 * IMPLEMENTOR="Eclipse Adoptium"
 * JAVA_VERSION="17.0.11"
 * IMAGE_TYPE="JRE"
 * MODULES="java.base java.logging java.xml ..."
 * 
 * @param content - Raw content of /opt/java/openjdk/release file
 * @returns Parsed metadata or null if parsing fails
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
      // Skip empty lines or comments
      if (!trimmedLine || trimmedLine.startsWith("#")) {
        continue;
      }
      
      // Parse KEY="VALUE" or KEY=VALUE format
      const equalsIndex = trimmedLine.indexOf("=");
      if (equalsIndex === -1) {
        continue; // Skip lines without '='
      }
      
      const key = trimmedLine.substring(0, equalsIndex).trim();
      let value = trimmedLine.substring(equalsIndex + 1).trim();
      
      // Remove surrounding quotes
      if ((value.startsWith('"') && value.endsWith('"')) ||
          (value.startsWith("'") && value.endsWith("'"))) {
        value = value.substring(1, value.length - 1);
      }
      
      properties[key] = value;
    }
    
    // extract JAVA_VERSION (required)
    const javaVersion = properties.JAVA_VERSION;
    if (!javaVersion) {
      return null; // 
    }
    return {
      javaVersion,
      releaseFilePath: "", // This will be set by the caller
    };
  } catch (error) {
    return null;
  }
}

