export {
  BaseCycloneDXParser,
  CycloneDXComponent,
  CycloneDXDependency,
  CycloneDXDocument,
} from "./base-parser";
export { CycloneDXJSONParser } from "./json-parser";
export { CycloneDXXMLParser } from "./xml-parser";

import { SBOMDocument } from "../types";
import { CycloneDXJSONParser } from "./json-parser";
import { CycloneDXXMLParser } from "./xml-parser";

// Factory for creating appropriate CycloneDX parser
export function createCycloneDXParser(
  content: string,
): CycloneDXJSONParser | CycloneDXXMLParser | null {
  const parsers = [new CycloneDXJSONParser(), new CycloneDXXMLParser()];

  for (const parser of parsers) {
    if (parser.canParse(content)) {
      return parser;
    }
  }

  return null;
}

// Convenience function for parsing CycloneDX content
export function parseCycloneDXContent(content: string): SBOMDocument | null {
  const parser = createCycloneDXParser(content);
  return parser ? parser.parse(content) : null;
}
