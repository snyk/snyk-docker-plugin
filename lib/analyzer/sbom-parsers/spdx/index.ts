export { BaseSPDXParser, SPDXPackage } from "./base-parser";
export { SPDXJSONParser } from "./json-parser";
export { SPDXXMLParser } from "./xml-parser";
export { SPDXRDFParser } from "./rdf-parser";
export { SPDXYAMLParser } from "./yaml-parser";

import { SBOMDocument } from "../types";
import { SPDXJSONParser } from "./json-parser";
import { SPDXRDFParser } from "./rdf-parser";
import { SPDXXMLParser } from "./xml-parser";
import { SPDXYAMLParser } from "./yaml-parser";

// Factory for creating appropriate SPDX parser
export function createSPDXParser(
  content: string,
): SPDXJSONParser | SPDXXMLParser | SPDXRDFParser | SPDXYAMLParser | null {
  const parsers = [
    new SPDXJSONParser(),
    new SPDXXMLParser(),
    new SPDXRDFParser(),
    new SPDXYAMLParser(),
  ];

  for (const parser of parsers) {
    if (parser.canParse(content)) {
      return parser;
    }
  }

  return null;
}

// Convenience function for parsing SPDX content
export function parseSPDXContent(content: string): SBOMDocument | null {
  const parser = createSPDXParser(content);
  return parser ? parser.parse(content) : null;
}
