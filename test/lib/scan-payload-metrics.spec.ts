import { computeScanPayloadMetrics } from "../../lib/scan-payload-metrics";
import type { ScanResult } from "../../lib/types";

function scanResult(image: string): ScanResult {
  return {
    target: { image },
    identity: { type: "deb", args: undefined },
    facts: [],
  };
}

describe("computeScanPayloadMetrics", () => {
  it("counts OS + app results and payload sizes", () => {
    const scanResults = [
      scanResult("os"),
      scanResult("app-a"),
      scanResult("app-b"),
    ];
    const m = computeScanPayloadMetrics(scanResults);

    expect(m.scanResultCount).toBe(3);
    expect(m.applicationScanResultCount).toBe(2);
    expect(m.scanResultPayloadBytes).toHaveLength(3);
    expect(m.scanResultPayloadBytes.every((n) => n > 0)).toBe(true);
    expect(m.totalScanResultsPayloadBytes).toBe(
      Buffer.byteLength(JSON.stringify(scanResults), "utf8"),
    );
  });

  it("empty scanResults", () => {
    expect(computeScanPayloadMetrics([])).toEqual({
      scanResultCount: 0,
      applicationScanResultCount: 0,
      scanResultPayloadBytes: [],
      totalScanResultsPayloadBytes: 2,
    });
  });
});
