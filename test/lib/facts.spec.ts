import { facts } from "../../lib/index";
import { Fact, FactType } from "../../lib/types";

describe("Facts", () => {
  it("correctly compiles and exports all the supported facts", () => {
    const depGraphFact: facts.DepGraphFact = {
      type: "depGraph",
      data: {} as any,
    };
    const dockerfileAnalysisFact: facts.DockerfileAnalysisFact = {
      type: "dockerfileAnalysis",
      data: {} as any,
    };
    const imageIdFact: facts.ImageIdFact = {
      type: "imageId",
      data: "",
    };
    const imageLayersFact: facts.ImageLayersFact = {
      type: "imageLayers",
      data: [],
    };
    const imageManifestFilesFact: facts.ImageManifestFilesFact = {
      type: "imageManifestFiles",
      data: [],
    };
    const imageOsReleasePrettyNameFact: facts.ImageOsReleasePrettyNameFact = {
      type: "imageOsReleasePrettyName",
      data: "",
    };
    const jarFingerprintsFact: facts.JarFingerprintsFact = {
      type: "jarFingerprints",
      data: {} as any,
    };
    const keyBinariesHashesFact: facts.KeyBinariesHashesFact = {
      type: "keyBinariesHashes",
      data: [],
    };
    const rootFsFact: facts.RootFsFact = {
      type: "rootFs",
      data: [],
    };
    const testedFilesFact: facts.TestedFilesFact = {
      type: "testedFiles",
      data: [],
    };
    const autoDetectedUserInstructionsFact: facts.AutoDetectedUserInstructionsFact =
      {
        type: "autoDetectedUserInstructions",
        data: {} as any,
      };
    const loadedPackagesFact: facts.LoadedPackagesFact = {
      type: "loadedPackages",
      data: {} as any,
    };
    const imageCreationTimeFact: facts.ImageCreationTimeFact = {
      type: "imageCreationTime",
      data: "",
    };

    // This would catch compilation errors.
    const allFacts: Fact[] = [
      depGraphFact,
      dockerfileAnalysisFact,
      imageIdFact,
      imageLayersFact,
      imageManifestFilesFact,
      imageOsReleasePrettyNameFact,
      jarFingerprintsFact,
      keyBinariesHashesFact,
      rootFsFact,
      testedFilesFact,
      autoDetectedUserInstructionsFact,
      imageCreationTimeFact,
      loadedPackagesFact,
    ];
    expect(allFacts).toBeDefined();

    const allFactsTypes: FactType[] = allFacts.map((fact) => fact.type);
    expect(allFactsTypes).toBeDefined();
  });
});
