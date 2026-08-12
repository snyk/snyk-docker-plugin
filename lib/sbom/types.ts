export interface CycloneDxComponent {
  type: "library";
  name: string;
  version?: string;
  "bom-ref": string;
}

export interface CycloneDxDocument {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  version: 1;
  components: CycloneDxComponent[];
  serialNumber?: string;
  metadata?: {
    timestamp?: string;
  };
}

export interface DepGraphsToCycloneDxOptions {
  serialNumber?: string;
  timestamp?: string;
}
