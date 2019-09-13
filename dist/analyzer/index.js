"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const Debug = require("debug");
const docker_1 = require("../docker");
const apkAnalyzer = require("./apk-analyzer");
const aptAnalyzer = require("./apt-analyzer");
const binariesAnalyzer = require("./binaries-analyzer");
const imageInspector = require("./image-inspector");
const osReleaseDetector = require("./os-release-detector");
const rpmAnalyzer = require("./rpm-analyzer");
const debug = Debug("snyk");
const extractActions = [
    ...aptAnalyzer.APT_PKGPATHS,
    ...apkAnalyzer.APK_PKGPATHS,
    ...osReleaseDetector.OS_VERPATHS,
].map((p) => {
    return {
        name: "txt",
        pattern: p,
    };
});
function analyze(targetImage, dockerfileAnalysis, options, dockerArchivePath) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const docker = new docker_1.Docker(targetImage, options);
        yield docker.scanStaticalyIfNeeded(extractActions, dockerArchivePath);
        const [imageInspection, osRelease] = yield Promise.all([
            imageInspector.detect(docker),
            osReleaseDetector.detect(docker, dockerfileAnalysis),
        ]);
        const results = yield Promise.all([
            apkAnalyzer.analyze(docker),
            aptAnalyzer.analyze(docker),
            rpmAnalyzer.analyze(docker),
        ]).catch((err) => {
            debug(`Error while running analyzer: '${err.stderr}'`);
            throw new Error("Failed to detect installed OS packages");
        });
        const { installedPackages, pkgManager } = getInstalledPackages(results);
        let binaries;
        try {
            binaries = yield binariesAnalyzer.analyze(targetImage, installedPackages, pkgManager, options);
        }
        catch (err) {
            debug(`Error while running binaries analyzer: '${err}'`);
            throw new Error("Failed to detect binaries versions");
        }
        return {
            imageId: imageInspection.Id,
            osRelease,
            results,
            binaries,
            imageLayers: imageInspection.RootFS && imageInspection.RootFS.Layers,
        };
    });
}
exports.analyze = analyze;
function getInstalledPackages(results) {
    const dockerAnalysis = results.find((res) => {
        return res.Analysis && res.Analysis.length > 0;
    });
    if (!dockerAnalysis) {
        return { installedPackages: [] };
    }
    const installedPackages = dockerAnalysis.Analysis.map((pkg) => pkg.Name);
    let pkgManager = dockerAnalysis.AnalyzeType;
    if (pkgManager) {
        pkgManager = pkgManager.toLowerCase();
    }
    return { installedPackages, pkgManager };
}
//# sourceMappingURL=index.js.map