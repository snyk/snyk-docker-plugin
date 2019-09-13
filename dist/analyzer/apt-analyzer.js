"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const APT_DPKG_STATUS = "/var/lib/dpkg/status";
const APT_EXT_STATES = "/var/lib/apt/extended_states";
const APT_PKGPATHS = [APT_DPKG_STATUS, APT_EXT_STATES];
exports.APT_PKGPATHS = APT_PKGPATHS;
function analyze(docker) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const dpkgFile = yield docker.getTextFile(APT_DPKG_STATUS);
        const pkgs = dpkgFile ? parseDpkgFile(dpkgFile) : [];
        const extFile = yield docker.getTextFile(APT_EXT_STATES);
        if (extFile) {
            setAutoInstalledPackages(extFile, pkgs);
        }
        return {
            Image: docker.getTargetImage(),
            AnalyzeType: "Apt",
            Analysis: pkgs,
        };
    });
}
exports.analyze = analyze;
function parseDpkgFile(text) {
    const pkgs = [];
    let curPkg = null;
    for (const line of text.split("\n")) {
        curPkg = parseDpkgLine(line, curPkg, pkgs);
    }
    return pkgs;
}
function parseDpkgLine(text, curPkg, pkgs) {
    const [key, value] = text.split(": ");
    switch (key) {
        case "Package":
            curPkg = {
                Name: value,
                Version: undefined,
                Source: undefined,
                Provides: [],
                Deps: {},
                AutoInstalled: undefined,
            };
            pkgs.push(curPkg);
            break;
        case "Version":
            curPkg.Version = value;
            break;
        case "Source":
            curPkg.Source = value.trim().split(" ")[0];
            break;
        case "Provides":
            for (let name of value.split(",")) {
                name = name.trim().split(" ")[0];
                curPkg.Provides.push(name);
            }
            break;
        case "Pre-Depends":
        case "Depends":
            for (const depElem of value.split(",")) {
                for (let name of depElem.split("|")) {
                    name = name.trim().split(" ")[0];
                    curPkg.Deps[name] = true;
                }
            }
            break;
    }
    return curPkg;
}
function setAutoInstalledPackages(text, pkgs) {
    const autoPkgs = parseExtFile(text);
    for (const pkg of pkgs) {
        if (autoPkgs[pkg.Name]) {
            pkg.AutoInstalled = true;
        }
    }
}
function parseExtFile(text) {
    const pkgMap = {};
    let curPkgName = null;
    for (const line of text.split("\n")) {
        curPkgName = parseExtLine(line, curPkgName, pkgMap);
    }
    return pkgMap;
}
function parseExtLine(text, curPkgName, pkgMap) {
    const [key, value] = text.split(": ");
    switch (key) {
        case "Package":
            curPkgName = value;
            break;
        case "Auto-Installed":
            if (parseInt(value, 10) === 1) {
                pkgMap[curPkgName] = true;
            }
            break;
    }
    return curPkgName;
}
//# sourceMappingURL=apt-analyzer.js.map