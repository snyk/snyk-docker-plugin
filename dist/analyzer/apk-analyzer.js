"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const APK_DB_INSTALLED = "/lib/apk/db/installed";
const APK_PKGPATHS = [APK_DB_INSTALLED];
exports.APK_PKGPATHS = APK_PKGPATHS;
function analyze(docker) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const pkgs = yield getPackages(docker);
        return {
            Image: docker.getTargetImage(),
            AnalyzeType: "Apk",
            Analysis: pkgs,
        };
    });
}
exports.analyze = analyze;
function getPackages(docker) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const dbFileContent = yield docker.getTextFile(APK_DB_INSTALLED);
        const pkgs = dbFileContent ? parseFile(dbFileContent) : [];
        return pkgs;
    });
}
function parseFile(text) {
    const pkgs = [];
    let curPkg = null;
    for (const line of text.split("\n")) {
        curPkg = parseLine(line, curPkg, pkgs);
    }
    return pkgs;
}
function parseLine(text, curPkg, pkgs) {
    const key = text.charAt(0);
    const value = text.substr(2);
    switch (key) {
        case "P": // Package
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
        case "V": // Version
            curPkg.Version = value;
            break;
        case "p": // Provides
            for (let name of value.split(" ")) {
                name = name.split("=")[0];
                curPkg.Provides.push(name);
            }
            break;
        case "r": // Depends
        case "D": // Depends
            // tslint:disable-next-line:no-duplicate-variable
            for (let name of value.split(" ")) {
                if (name.charAt(0) !== "!") {
                    name = name.split("=")[0];
                    curPkg.Deps[name] = true;
                }
            }
            break;
    }
    return curPkg;
}
//# sourceMappingURL=apk-analyzer.js.map