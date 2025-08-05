import {
  createCycloneDXParser,
  CycloneDXJSONParser,
  CycloneDXXMLParser,
} from "./cyclonedx/index";
import { SBOMDocument } from "./types";

/**
 * Parse CycloneDX JSON format using the dedicated JSON parser
 */
export function parseCycloneDXJSON(content: string): SBOMDocument | null {
  const parser = new CycloneDXJSONParser();
  return parser.canParse(content) ? parser.parse(content) : null;
}

/**
 * Parse CycloneDX XML format using the dedicated XML parser
 */
export function parseCycloneDXXML(content: string): SBOMDocument | null {
  const parser = new CycloneDXXMLParser();
  return parser.canParse(content) ? parser.parse(content) : null;
}

/**
 * Auto-detect and parse any CycloneDX format
 */
export function parseCycloneDXAuto(content: string): SBOMDocument | null {
  const parser = createCycloneDXParser(content);
  return parser ? parser.parse(content) : null;
}
