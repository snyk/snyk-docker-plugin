/**
 * Stabilize PluginResponse.analytics in snapshots.
 *
 * `containerPluginTimings.data` holds wall-clock durations (e.g. nodeAnalysisMs)
 * that are non-deterministic, but the KEY names are an analytics contract we want
 * pinned. So we snapshot a timings object with its keys intact and every value
 * blanked to "<ms>". Everything else in analytics (e.g. containerScanPayloadMetrics)
 * is deterministic — PLUGIN_VERSION is "0.0.0-local" — and is snapshotted in full.
 *
 * A timings object is recognized structurally: a non-empty object whose values are
 * all numbers. containerScanPayloadMetrics is excluded because it carries an array
 * value (scanResultPayloadBytes). Blanking yields string values, so the predicate no
 * longer matches the result — this is the recursion guard.
 *
 * Plain JS so it loads before ts-jest (needed for the Windows Jest config).
 */
expect.addSnapshotSerializer({
  test(val) {
    if (val === null || typeof val !== "object" || Array.isArray(val)) {
      return false;
    }
    const values = Object.values(val);
    return values.length > 0 && values.every((v) => typeof v === "number");
  },
  serialize(val, config, indentation, depth, refs, printer) {
    const blanked = {};
    for (const key of Object.keys(val)) {
      blanked[key] = "<ms>";
    }
    return printer(blanked, config, indentation, depth, refs);
  },
});
