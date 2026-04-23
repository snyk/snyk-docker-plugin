import {
  BaseImageLifecycleStatus,
  BaseImageLifecycleStatusFact,
  facts,
} from "../../lib/index";
import { Fact, FactType } from "../../lib/types";

describe("BaseImageLifecycleStatus feature", () => {
  describe("BaseImageLifecycleStatusFact structure", () => {
    it("accepts 'eol' lifecycle status with isEol=true and an eolDate", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: {
          lifecycleStatus: "eol",
          isEol: true,
          eolDate: "2024-04-01",
        },
      };

      expect(fact.type).toBe("baseImageLifecycleStatus");
      expect(fact.data.lifecycleStatus).toBe("eol");
      expect(fact.data.isEol).toBe(true);
      expect(fact.data.eolDate).toBe("2024-04-01");
    });

    it("accepts 'supported' lifecycle status with isEol=false and no eolDate", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: {
          lifecycleStatus: "supported",
          isEol: false,
        },
      };

      expect(fact.data.lifecycleStatus).toBe("supported");
      expect(fact.data.isEol).toBe(false);
      expect(fact.data.eolDate).toBeUndefined();
    });

    it("accepts 'unknown' lifecycle status with isEol=false and no eolDate", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: {
          lifecycleStatus: "unknown",
          isEol: false,
        },
      };

      expect(fact.data.lifecycleStatus).toBe("unknown");
      expect(fact.data.isEol).toBe(false);
      expect(fact.data.eolDate).toBeUndefined();
    });

    it("is assignable to the generic Fact type", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: {
          lifecycleStatus: "eol",
          isEol: true,
          eolDate: "2025-06-30",
        },
      };

      // This assignment would fail at compile time if the type is wrong.
      const genericFact: Fact = fact;
      expect(genericFact.type).toBe("baseImageLifecycleStatus");
      expect(genericFact.data.isEol).toBe(true);
    });

    it("can be included in a ScanResult facts array alongside other facts", () => {
      const eolFact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: {
          lifecycleStatus: "eol",
          isEol: true,
          eolDate: "2023-11-01",
        },
      };

      const otherFact: facts.ImageIdFact = {
        type: "imageId",
        data: "sha256:abc123",
      };

      const factsList: Fact[] = [eolFact, otherFact];

      const found = factsList.find((f) => f.type === "baseImageLifecycleStatus");
      expect(found).toBeDefined();
      expect(found!.data.lifecycleStatus).toBe("eol");
      expect(found!.data.isEol).toBe(true);
      expect(found!.data.eolDate).toBe("2023-11-01");
    });
  });

  describe("FactType union includes 'baseImageLifecycleStatus'", () => {
    it("allows 'baseImageLifecycleStatus' as a valid FactType value", () => {
      const factType: FactType = "baseImageLifecycleStatus";
      expect(factType).toBe("baseImageLifecycleStatus");
    });

    it("is the declared type of BaseImageLifecycleStatusFact", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "supported", isEol: false },
      };
      // fact.type must be statically narrowed to the literal "baseImageLifecycleStatus"
      const typed: FactType = fact.type;
      expect(typed).toBe("baseImageLifecycleStatus");
    });
  });

  describe("BaseImageLifecycleStatus type values", () => {
    it("has exactly the three expected status values", () => {
      const statuses: BaseImageLifecycleStatus[] = [
        "supported",
        "eol",
        "unknown",
      ];
      expect(statuses).toHaveLength(3);
      expect(statuses).toContain("supported");
      expect(statuses).toContain("eol");
      expect(statuses).toContain("unknown");
    });
  });

  describe("isEol convenience flag", () => {
    it("should be true only when lifecycleStatus is 'eol'", () => {
      const eolFact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "eol", isEol: true },
      };
      const supportedFact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "supported", isEol: false },
      };
      const unknownFact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "unknown", isEol: false },
      };

      expect(eolFact.data.isEol).toBe(true);
      expect(supportedFact.data.isEol).toBe(false);
      expect(unknownFact.data.isEol).toBe(false);
    });
  });

  describe("public API exports", () => {
    it("exports BaseImageLifecycleStatusFact from the package index", () => {
      // If this compiles and the import resolves, the export is present.
      // Verify it's a usable type by constructing one.
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "supported", isEol: false },
      };
      expect(fact.type).toBe("baseImageLifecycleStatus");
    });

    it("exports BaseImageLifecycleStatus type from the package index", () => {
      const status: BaseImageLifecycleStatus = "eol";
      expect(status).toBe("eol");
    });

    it("exposes BaseImageLifecycleStatusFact via the facts namespace", () => {
      // The facts namespace should contain the fact type
      const fact: facts.BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "eol", isEol: true, eolDate: "2024-01-01" },
      };
      expect(fact.data.lifecycleStatus).toBe("eol");
      expect(fact.data.isEol).toBe(true);
      expect(fact.data.eolDate).toBe("2024-01-01");
    });
  });

  describe("eolDate field", () => {
    it("is optional and absent when status is 'supported'", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "supported", isEol: false },
      };
      expect("eolDate" in fact.data).toBe(false);
    });

    it("is optional and absent when status is 'unknown'", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "unknown", isEol: false },
      };
      expect("eolDate" in fact.data).toBe(false);
    });

    it("is present when status is 'eol' and a date is known", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: {
          lifecycleStatus: "eol",
          isEol: true,
          eolDate: "2022-09-30",
        },
      };
      expect(fact.data.eolDate).toBe("2022-09-30");
    });

    it("is absent even for 'eol' when the date is not yet known", () => {
      const fact: BaseImageLifecycleStatusFact = {
        type: "baseImageLifecycleStatus",
        data: { lifecycleStatus: "eol", isEol: true },
      };
      expect(fact.data.eolDate).toBeUndefined();
    });
  });
});
