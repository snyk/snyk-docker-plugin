import * as Debug from "debug";

const debug = Debug("snyk:sbom:xml-utils");

/**
 * Extract a single XML element value using regex patterns
 * Supports various XML formats including namespaced elements
 */
export function extractXMLValue(
  content: string,
  tagNames: string[],
): string | null {
  for (const tagName of tagNames) {
    // Try different regex patterns for XML elements
    const patterns = [
      // Standard element: <tag>value</tag>
      new RegExp(`<${tagName}[^>]*>([^<]+)</${tagName}>`, "i"),
      // CDATA element: <tag><![CDATA[value]]></tag>
      new RegExp(
        `<${tagName}[^>]*>\\s*<!\\[CDATA\\[([^\\]]+)\\]\\]>\\s*</${tagName}>`,
        "i",
      ),
      // Attribute: tag="value"
      new RegExp(`${tagName}=["']([^"']+)["']`, "i"),
      // Self-closing with text: <tag text="value" />
      new RegExp(`<${tagName}[^>]*\\s+[^>]*>([^<]+)`, "i"),
    ];

    for (const pattern of patterns) {
      const match = content.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
  }
  return null;
}

/**
 * Extract XML attribute value from an element
 */
export function extractXMLAttribute(
  content: string,
  elementName: string,
  attributeName: string,
): string | null {
  // Pattern to match attribute within a specific element (including at start of tag)
  const patterns = [
    new RegExp(
      `<${elementName}[^>]*\\s+${attributeName}=["']([^"']+)["']`,
      "i",
    ),
    new RegExp(`<${elementName}[^>]*\\s${attributeName}=["']([^"']+)["']`, "i"),
    new RegExp(
      `<${elementName}\\s+[^>]*${attributeName}=["']([^"']+)["']`,
      "i",
    ),
  ];

  for (const pattern of patterns) {
    const match = content.match(pattern);
    if (match) {
      return match[1].trim();
    }
  }
  return null;
}

/**
 * Extract XML blocks (elements with their content) using regex patterns
 * Returns array of full element blocks including their tags
 */
export function extractXMLBlocks(
  content: string,
  tagNames: string[],
): string[] {
  const blocks: string[] = [];

  for (const tagName of tagNames) {
    // Pattern to match opening and closing tags with their content
    const pattern = new RegExp(
      `<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`,
      "gi",
    );
    let match = pattern.exec(content);
    while (match !== null) {
      blocks.push(match[0]); // Include the full element with tags
      match = pattern.exec(content);
    }
  }

  return blocks;
}

/**
 * Extract multiple values for the same tag (e.g., multiple <creator> elements)
 */
export function extractXMLMultipleValues(
  content: string,
  tagNames: string[],
): string[] {
  const values: string[] = [];

  for (const tagName of tagNames) {
    const pattern = new RegExp(`<${tagName}[^>]*>([^<]+)</${tagName}>`, "gi");
    let match = pattern.exec(content);
    while (match !== null) {
      if (match[1]) {
        values.push(match[1].trim());
      }
      match = pattern.exec(content);
    }
  }

  return values;
}

/**
 * Check if content is XML by looking for XML declaration or root elements
 */
export function isXMLContent(content: string): boolean {
  const trimmed = content.trim();
  return (
    trimmed.startsWith("<?xml") ||
    trimmed.startsWith("<") ||
    /<[^>]+>/.test(trimmed.substring(0, 100))
  );
}

/**
 * Extract nested XML structure (useful for complex elements like external references)
 */
export function extractNestedXMLStructure(
  content: string,
  containerTag: string,
  childTags: string[],
): Array<{ [key: string]: string }> {
  const results: Array<{ [key: string]: string }> = [];
  const containerBlocks = extractXMLBlocks(content, [containerTag]);

  for (const block of containerBlocks) {
    const item: { [key: string]: string } = {};

    for (const childTag of childTags) {
      const value = extractXMLValue(block, [childTag]);
      if (value) {
        item[childTag] = value;
      }
    }

    if (Object.keys(item).length > 0) {
      results.push(item);
    }
  }

  return results;
}

/**
 * Parse XML component/package structure common to both SPDX and CycloneDX
 */
export interface XMLPackageBase {
  name: string;
  version: string;
  id?: string; // SPDX ID or bom-ref
  purl?: string;
  license?: string;
  supplier?: string;
  downloadLocation?: string;
  checksums?: { [algorithm: string]: string };
  copyrightText?: string;
  dependencies?: string[];
}

/**
 * Extract checksums from XML content
 */
export function extractXMLChecksums(
  content: string,
  checksumTags: string[],
  algorithmTags: string[],
  valueTags: string[],
): { [algorithm: string]: string } {
  const checksums: { [algorithm: string]: string } = {};
  const checksumBlocks = extractXMLBlocks(content, checksumTags);

  for (const checksumBlock of checksumBlocks) {
    const algorithm = extractXMLValue(checksumBlock, algorithmTags);
    const checksumValue = extractXMLValue(checksumBlock, valueTags);

    if (algorithm && checksumValue) {
      checksums[algorithm.toLowerCase()] = checksumValue;
    }
  }

  return checksums;
}

/**
 * Validate that required fields are present in parsed data
 */
export function validateRequiredFields(
  data: any,
  requiredFields: string[],
): boolean {
  for (const field of requiredFields) {
    if (!data[field]) {
      debug(`Missing required field: ${field}`);
      return false;
    }
  }
  return true;
}

/**
 * Normalize text content by removing extra whitespace and handling CDATA
 */
export function normalizeXMLText(text: string): string {
  return text
    .replace(/^\s*<!\[CDATA\[/, "") // Remove CDATA start
    .replace(/\]\]>\s*$/, "") // Remove CDATA end
    .replace(/\s+/g, " ") // Normalize whitespace
    .trim();
}
