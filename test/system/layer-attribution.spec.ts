import * as plugin from "../../lib";
import { LayerPackageAttributionFact } from "../../lib/facts";
import { getFixture } from "../util";

// End-to-end check for the `layerPackageAttribution` fact against a real
// docker-archive fixture. The fixture is built from a hand-crafted
// Dockerfile (see the scenario walkthrough below) and is designed to
// exercise every branch of the dual-output contract:
//
//   - Layer 0 (FROM alpine:3.19) introduces the alpine base packages — all
//     survive to the final image.
//   - LABEL / ENV / WORKDIR are empty_layer history entries and so produce
//     no rootfs layer; nothing to attribute.
//   - `RUN apk add tmux` introduces tmux + its transitive deps (libevent,
//     ncurses pieces). All survive.
//   - `COPY Dockerfile /app/` produces a rootfs layer with no package-DB
//     change; the attributor must skip it (no entry, no shifted indices).
//   - `RUN apk add jq htop` introduces jq, oniguruma, htop. htop is the
//     shadow / remediated-vuln case: present in `entries[]` but absent
//     from `finalImagePackages` because the next layer removes it and it
//     never comes back.
//   - `RUN apk add bash && apk del jq htop` introduces bash + readline.
//     The deletions are intentionally silent in the output (the producer
//     no longer emits `removedPackages`; consumers derive removals as
//     `entries[] \ finalImagePackages`).
//   - EXPOSE 80 is empty_layer — no rootfs layer, no entry.
//   - `RUN apk add jq` reinstalls jq + oniguruma at the same versions as
//     entry 2. They re-appear in `entries[]` here (raw event stream), and
//     `finalImagePackages` attributes them to THIS layer, not the earlier
//     one — proving `latestIntroductionByKey` overwrites on reinstall.

describe("layerPackageAttribution fact on a real image", () => {
  const archivePath = getFixture([
    "docker-archives",
    "docker-save",
    "layer-attribution-test.tar",
  ]);

  let attribution: LayerPackageAttributionFact["data"];

  beforeAll(async () => {
    const pluginResult = await plugin.scan({
      path: `docker-archive:${archivePath}`,
      "layer-attribution": true,
    });

    const fact = pluginResult.scanResults[0].facts.find(
      (f) => f.type === "layerPackageAttribution",
    ) as LayerPackageAttributionFact | undefined;

    if (!fact) {
      throw new Error(
        "expected a layerPackageAttribution fact on the scan result",
      );
    }
    attribution = fact.data;
  });

  it("emits the fact only when --layer-attribution is enabled", async () => {
    const withoutOpt = await plugin.scan({
      path: `docker-archive:${archivePath}`,
    });
    const fact = withoutOpt.scanResults[0].facts.find(
      (f) => f.type === "layerPackageAttribution",
    );
    expect(fact).toBeUndefined();
  });

  describe("entries (raw introduction event stream)", () => {
    it("only emits entries for layers that mutate the package DB", () => {
      // We expect entries for: FROM (0), `apk add tmux`, `apk add jq htop`,
      // `apk add bash && apk del jq htop`, `apk add jq`. The LABEL / ENV /
      // WORKDIR / EXPOSE history entries are empty_layer (no rootfs layer)
      // and the COPY layer has no DB change, so neither produces an entry.
      expect(attribution.entries).toHaveLength(5);
    });

    it("orders entries by ascending layerIndex with gaps for skipped layers", () => {
      const indices = attribution.entries.map((e) => e.layerIndex);
      expect(indices).toEqual([...indices].sort((a, b) => a - b));
      // The COPY layer sits between the tmux and `apk add jq htop` layers,
      // so the layerIndex sequence must contain a gap (no consecutive run).
      const gaps = indices
        .slice(1)
        .map((idx, i) => idx - indices[i])
        .filter((d) => d > 1);
      expect(gaps.length).toBeGreaterThan(0);
    });

    it("annotates each entry with diffID, digest, and instruction", () => {
      for (const entry of attribution.entries) {
        expect(entry.diffID).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(entry.digest).toBeDefined();
        expect(entry.instruction).toBeDefined();
        expect(entry.packages.length).toBeGreaterThan(0);
      }
    });

    it("attributes the alpine base packages to entry 0", () => {
      const base = attribution.entries[0];
      expect(base.layerIndex).toBe(0);
      expect(base.instruction).toMatch(/alpine-minirootfs/);
      // Spot-check core alpine pieces. The full list (~15 packages) is the
      // stock alpine:3.19 set; we don't pin it to a specific count to keep
      // the test resilient to upstream point releases of the base image.
      // Keys are `<origin>/<binary>@<version>` when apk records an `o:`
      // line (almost always for alpine base packages — `o:` matches the
      // binary name for these stand-alone packages, e.g. `busybox/busybox`),
      // matching the dep-graph node name. Anchor on the trailing
      // `/<binary>@` so the assertion stays readable without committing to
      // the specific origin string.
      expect(base.packages).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/(?:^|\/)alpine-baselayout@/),
          expect.stringMatching(/(?:^|\/)busybox@/),
          expect.stringMatching(/(?:^|\/)musl@/),
          expect.stringMatching(/(?:^|\/)apk-tools@/),
        ]),
      );
    });

    it("attributes tmux and its transitive deps to the `apk add tmux` layer", () => {
      const tmuxEntry = attribution.entries.find((e) =>
        e.packages.some((p) => /(?:^|\/)tmux@/.test(p)),
      );
      expect(tmuxEntry).toBeDefined();
      expect(tmuxEntry!.instruction).toMatch(/apk add --no-cache tmux/);
      // `libncursesw` is part of the `ncurses` source/origin, so its key
      // is `ncurses/libncursesw@…`. Allow either the bare or the prefixed
      // form so the test isn't coupled to a specific apkindex layout.
      expect(tmuxEntry!.packages).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/(?:^|\/)tmux@/),
          expect.stringMatching(/(?:^|\/)libevent@/),
          expect.stringMatching(/(?:^|\/)libncursesw@/),
        ]),
      );
    });

    it("records htop as an introduction even though it is removed later", () => {
      // Shadow / remediated-vuln case: htop is installed by `apk add jq
      // htop` and purged by the next RUN. It must remain visible in
      // `entries[]` (raw event stream) but be absent from
      // `finalImagePackages` (live set) — see the next describe block.
      const htopEntry = attribution.entries.find((e) =>
        e.packages.some((p) => /(?:^|\/)htop@/.test(p)),
      );
      expect(htopEntry).toBeDefined();
      expect(htopEntry!.instruction).toMatch(/apk add --no-cache jq htop/);
      // The same entry also introduces jq + oniguruma; bash is in the next.
      expect(htopEntry!.packages).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/(?:^|\/)htop@/),
          expect.stringMatching(/(?:^|\/)jq@/),
          expect.stringMatching(/(?:^|\/)oniguruma@/),
        ]),
      );
    });

    it("re-emits jq and oniguruma on the reinstall layer", () => {
      // After the previous layer purged jq, it is absent from
      // previousPkgs, so reinstalling it at the same version counts as a
      // new introduction event — the raw event stream is honest about
      // install→remove→reinstall sequences.
      const jqEntries = attribution.entries.filter((e) =>
        e.packages.some((p) => /(?:^|\/)jq@/.test(p)),
      );
      expect(jqEntries).toHaveLength(2);

      const reinstall = jqEntries[jqEntries.length - 1];
      expect(reinstall.instruction).toMatch(/apk add --no-cache jq/);
      expect(reinstall.instruction).not.toMatch(/htop/);
      expect(reinstall.packages).toEqual(
        expect.arrayContaining([
          expect.stringMatching(/(?:^|\/)jq@/),
          expect.stringMatching(/(?:^|\/)oniguruma@/),
        ]),
      );
    });
  });

  describe("finalImagePackages (live-set index)", () => {
    it("contains every surviving package with a length-1 origin list", () => {
      // OS package managers dedupe — there is only one live copy of any
      // given name@version on disk, so every list must be length 1.
      const values = Object.values(attribution.finalImagePackages);
      expect(values.length).toBeGreaterThan(0);
      for (const origins of values) {
        expect(origins).toHaveLength(1);
        expect(origins[0].layerIndex).toEqual(expect.any(Number));
        expect(origins[0].diffID).toMatch(/^sha256:[0-9a-f]{64}$/);
      }
    });

    it("omits htop — it was installed and later purged", () => {
      // Shadow vuln signal: htop is in `entries[].packages` but absent
      // here. A consumer doing `entries \ finalImagePackages` recovers
      // it as a remediated package.
      const htopKeys = Object.keys(attribution.finalImagePackages).filter((k) =>
        /(?:^|\/)htop@/.test(k),
      );
      expect(htopKeys).toEqual([]);

      const htopInEntries = attribution.entries
        .flatMap((e) => e.packages)
        .some((p) => /(?:^|\/)htop@/.test(p));
      expect(htopInEntries).toBe(true);
    });

    it("attributes tmux's live copy to the `apk add tmux` layer", () => {
      const tmuxKey = Object.keys(attribution.finalImagePackages).find((k) =>
        /(?:^|\/)tmux@/.test(k),
      )!;
      expect(tmuxKey).toBeDefined();

      const [origin] = attribution.finalImagePackages[tmuxKey];
      const tmuxEntry = attribution.entries.find(
        (e) => e.layerIndex === origin.layerIndex,
      );
      expect(tmuxEntry?.instruction).toMatch(/apk add --no-cache tmux/);
    });

    it("attributes jq's live copy to the REINSTALL layer, not the first install", () => {
      // The load-bearing assertion for `latestIntroductionByKey`: when a
      // package is installed, removed, then reinstalled, the live-set
      // index must point at the most recent introduction — otherwise a
      // backend doing `finalImagePackages[jq@...] -> layer` would
      // attribute a live vuln to a layer whose copy of the package no
      // longer exists on disk.
      const jqKey = Object.keys(attribution.finalImagePackages).find((k) =>
        /(?:^|\/)jq@/.test(k),
      )!;
      expect(jqKey).toBeDefined();

      const [jqOrigin] = attribution.finalImagePackages[jqKey];
      const reinstallLayerIndex = Math.max(
        ...attribution.entries
          .filter((e) => e.packages.some((p) => /(?:^|\/)jq@/.test(p)))
          .map((e) => e.layerIndex),
      );
      expect(jqOrigin.layerIndex).toBe(reinstallLayerIndex);

      // And, symmetrically, the same is true for oniguruma — jq's
      // transitive dep that got dragged through the same install/remove/
      // reinstall cycle.
      const oniKey = Object.keys(attribution.finalImagePackages).find((k) =>
        /(?:^|\/)oniguruma@/.test(k),
      )!;
      const [oniOrigin] = attribution.finalImagePackages[oniKey];
      expect(oniOrigin.layerIndex).toBe(reinstallLayerIndex);
    });

    it("keeps `entries[]` and `finalImagePackages` consistent: every survivor's origin is one of its introductions", () => {
      for (const [key, origins] of Object.entries(
        attribution.finalImagePackages,
      )) {
        const [origin] = origins;
        const matchingEntry = attribution.entries.find(
          (e) => e.layerIndex === origin.layerIndex,
        );
        expect(matchingEntry).toBeDefined();
        expect(matchingEntry!.packages).toContain(key);
        expect(matchingEntry!.diffID).toBe(origin.diffID);
      }
    });
  });
});
