import {
  createSPDXParser,
  SPDXJSONParser,
  SPDXRDFParser,
  SPDXXMLParser,
  SPDXYAMLParser,
} from "./spdx/index";
import { SBOMDocument } from "./types";

/**
 * Parse SPDX JSON format using the dedicated JSON parser
 */
export function parseSPDXJSON(content: string): SBOMDocument | null {
  const parser = new SPDXJSONParser();
  return parser.canParse(content) ? parser.parse(content) : null;
}

/**
 * Parse SPDX XML format using the dedicated XML parser
 */
export function parseSPDXXML(content: string): SBOMDocument | null {
  const parser = new SPDXXMLParser();
  return parser.canParse(content) ? parser.parse(content) : null;
}

/**
 * Parse SPDX RDF format using the dedicated RDF parser
 */
export function parseSPDXRDF(content: string): SBOMDocument | null {
  const parser = new SPDXRDFParser();
  return parser.canParse(content) ? parser.parse(content) : null;
}

/**
 * Parse SPDX YAML format using the dedicated YAML parser
 */
export function parseSPDXYAML(content: string): SBOMDocument | null {
  const parser = new SPDXYAMLParser();
  return parser.canParse(content) ? parser.parse(content) : null;
}

/**
 * Auto-detect and parse any SPDX format
 */
export function parseSPDXAuto(content: string): SBOMDocument | null {
  const parser = createSPDXParser(content);
  return parser ? parser.parse(content) : null;
}
