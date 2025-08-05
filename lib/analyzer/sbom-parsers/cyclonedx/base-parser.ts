import * as Debug from "debug";
import { SBOMDocument, SBOMPackage } from "../types";

export interface CycloneDXComponent {
  type: string;
  "bom-ref"?: string;
  supplier?: {
    name: string;
    url?: string[];
  };
  author?: string;
  publisher?: string;
  group?: string;
  name: string;
  version: string;
  description?: string;
  scope?: string;
  hashes?: Array<{
    alg: string;
    content: string;
  }>;
  licenses?: Array<{
    license?: {
      id?: string;
      name?: string;
      url?: string;
    };
    expression?: string;
  }>;
  copyright?: string;
  cpe?: string;
  purl?: string;
  externalReferences?: Array<{
    type: string;
    url: string;
    comment?: string;
  }>;
}

export interface CycloneDXDependency {
  ref: string;
  dependsOn?: string[];
}

export interface CycloneDXDocument {
  bomFormat: string;
  specVersion: string;
  serialNumber?: string;
  version: number;
  metadata?: {
    timestamp?: string;
    tools?: Array<{
      vendor?: string;
      name?: string;
      version?: string;
    }>;
    authors?: Array<{
      name?: string;
      email?: string;
    }>;
    component?: CycloneDXComponent;
  };
  components?: CycloneDXComponent[];
  services?: any[];
  dependencies?: CycloneDXDependency[];
}

/**
 * Abstract base class for CycloneDX parsers
 */
export abstract class BaseCycloneDXParser {
  protected debug: Debug.Debugger;

  constructor(formatName: string) {
    this.debug = Debug(`snyk:sbom:cyclonedx:${formatName}`);
  }

  /**
   * Abstract method to parse CycloneDX content - must be implemented by subclasses
   */
  public abstract parse(content: string): SBOMDocument | null;

  /**
   * Validate if content can be parsed by this parser
   */
  public abstract canParse(content: string): boolean;

  /**
   * Convert CycloneDXComponent to SBOMPackage format
   */
  protected convertToSBOMPackage(component: CycloneDXComponent): SBOMPackage {
    // Extract license information
    let license: string | undefined;
    if (component.licenses && component.licenses.length > 0) {
      const licenseInfo = component.licenses[0];
      if (licenseInfo.expression) {
        license = licenseInfo.expression;
      } else if (licenseInfo.license) {
        license = licenseInfo.license.id || licenseInfo.license.name;
      }
    }

    // Extract supplier information
    let supplier: string | undefined;
    if (component.supplier?.name) {
      supplier = component.supplier.name;
    } else if (component.author) {
      supplier = component.author;
    } else if (component.publisher) {
      supplier = component.publisher;
    }

    // Extract download location from external references
    let downloadLocation: string | undefined;
    if (component.externalReferences) {
      // Prioritize distribution > website > vcs
      const distributionRef = component.externalReferences.find(
        (ref) => ref.type === "distribution",
      );
      const websiteRef = component.externalReferences.find(
        (ref) => ref.type === "website",
      );
      const vcsRef = component.externalReferences.find(
        (ref) => ref.type === "vcs",
      );

      downloadLocation = distributionRef?.url || websiteRef?.url || vcsRef?.url;
    }

    // Convert checksums
    const checksums: { [algorithm: string]: string } = {};
    if (component.hashes) {
      component.hashes.forEach((hash) => {
        checksums[hash.alg.toLowerCase()] = hash.content;
      });
    }

    // Build full name including group if present
    const fullName = component.group
      ? `${component.group}/${component.name}`
      : component.name;

    return {
      name: fullName,
      version: component.version || "unknown",
      purl: component.purl,
      license,
      supplier,
      downloadLocation,
      checksums,
      copyrightText: component.copyright,
      dependencies: [], // Will be populated by relationship processing
    };
  }

  /**
   * Process dependencies and populate dependency arrays
   */
  protected processDependencies(
    dependencies: CycloneDXDependency[],
    packages: SBOMPackage[],
    componentMap: Map<string, SBOMPackage>,
  ) {
    // Process dependencies
    dependencies.forEach((dep) => {
      const fromPkg = componentMap.get(dep.ref);
      if (fromPkg && dep.dependsOn) {
        fromPkg.dependencies = fromPkg.dependencies || [];
        dep.dependsOn.forEach((depRef) => {
          const toPkg = componentMap.get(depRef);
          if (toPkg) {
            fromPkg.dependencies!.push(toPkg.name);
          }
        });
      }
    });
  }

  /**
   * Build creation info from CycloneDX metadata
   */
  protected buildCreationInfo(metadata: CycloneDXDocument["metadata"]) {
    const creators: string[] = [];

    // Add tools as creators
    if (metadata?.tools) {
      metadata.tools.forEach((tool) => {
        const toolName = tool.name || "Unknown Tool";
        const toolVersion = tool.version ? `-${tool.version}` : "";
        const vendor = tool.vendor ? `${tool.vendor}: ` : "";
        creators.push(`Tool: ${vendor}${toolName}${toolVersion}`);
      });
    }

    // Add authors as creators
    if (metadata?.authors) {
      metadata.authors.forEach((author) => {
        const name = author.name || "Unknown Author";
        const email = author.email ? ` (${author.email})` : "";
        creators.push(`Person: ${name}${email}`);
      });
    }

    return {
      created: metadata?.timestamp || "",
      creators,
      licenseListVersion: undefined,
    };
  }

  /**
   * Build a standard SBOM document structure
   */
  protected buildSBOMDocument(
    name: string,
    version: string,
    serialNumber: string | undefined,
    metadata: CycloneDXDocument["metadata"],
    packages: SBOMPackage[],
  ): SBOMDocument {
    const creationInfo = this.buildCreationInfo(metadata);

    return {
      name,
      version,
      dataLicense: "Apache-2.0", // CycloneDX uses Apache license
      documentNamespace: serialNumber,
      creationInfo,
      packages,
    };
  }

  /**
   * Handle parsing errors consistently
   */
  protected handleError(error: any, context: string): null {
    this.debug(`Error parsing CycloneDX ${context}: ${error.message}`);
    return null;
  }

  /**
   * Validate CycloneDX document structure
   */
  protected validateDocument(doc: any): boolean {
    if (!doc.bomFormat || doc.bomFormat !== "CycloneDX") {
      this.debug("Invalid CycloneDX document: incorrect bomFormat");
      return false;
    }

    if (!doc.specVersion) {
      this.debug("Invalid CycloneDX document: missing specVersion");
      return false;
    }

    return true;
  }

  /**
   * Create a component map for dependency processing
   */
  protected createComponentMap(
    components: CycloneDXComponent[],
    packages: SBOMPackage[],
  ): Map<string, SBOMPackage> {
    const componentMap = new Map<string, SBOMPackage>();

    components.forEach((comp, index) => {
      const bomRef = comp["bom-ref"];
      if (bomRef && packages[index]) {
        componentMap.set(bomRef, packages[index]);
      }
    });

    return componentMap;
  }

  /**
   * Extract document name from CycloneDX document
   */
  protected extractDocumentName(doc: CycloneDXDocument): string {
    // Try to get name from metadata component
    if (doc.metadata?.component?.name) {
      return doc.metadata.component.name;
    }

    // Fallback to serial number or default
    return doc.serialNumber || "CycloneDX SBOM Document";
  }
}
