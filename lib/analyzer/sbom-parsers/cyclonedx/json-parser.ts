import { SBOMDocument } from "../types";
import {
  BaseCycloneDXParser,
  CycloneDXComponent,
  CycloneDXDocument,
} from "./base-parser";

/**
 * CycloneDX JSON format parser
 */
export class CycloneDXJSONParser extends BaseCycloneDXParser {
  constructor() {
    super("json");
  }

  public canParse(content: string): boolean {
    try {
      const trimmed = content.trim();
      if (!trimmed.startsWith("{")) {
        return false;
      }

      const parsed = JSON.parse(content);
      return !!(parsed.bomFormat === "CycloneDX" && parsed.specVersion);
    } catch {
      return false;
    }
  }

  public parse(content: string): SBOMDocument | null {
    try {
      const cdxDoc: CycloneDXDocument = JSON.parse(content);

      if (!this.validateDocument(cdxDoc)) {
        return null;
      }

      // Extract components
      const components = this.extractComponents(cdxDoc);

      // Convert components to SBOM packages
      const packages = components.map((comp) =>
        this.convertToSBOMPackage(comp),
      );

      // Process dependencies
      if (cdxDoc.dependencies) {
        const componentMap = this.createComponentMap(components, packages);
        this.processDependencies(cdxDoc.dependencies, packages, componentMap);
      }

      // Build final document
      const documentName = this.extractDocumentName(cdxDoc);
      const version = `CycloneDX-${cdxDoc.specVersion}`;

      return this.buildSBOMDocument(
        documentName,
        version,
        cdxDoc.serialNumber,
        cdxDoc.metadata,
        packages,
      );
    } catch (error) {
      return this.handleError(error, "JSON");
    }
  }

  private extractComponents(cdxDoc: CycloneDXDocument): CycloneDXComponent[] {
    const components: CycloneDXComponent[] = [];

    // Add metadata component if it exists
    if (cdxDoc.metadata?.component) {
      components.push(cdxDoc.metadata.component);
    }

    // Add regular components
    if (cdxDoc.components) {
      components.push(...cdxDoc.components);
    }

    return components;
  }
}
