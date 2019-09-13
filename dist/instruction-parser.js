"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Naive regex; see tests for cases
// tslint:disable-next-line:max-line-length
const installRegex = /\s*(rpm\s+-i|rpm\s+--install|apk\s+((--update|-u)\s+)*add|apt-get\s+((--assume-yes|--yes|-y)\s+)*install|apt\s+((--assume-yes|--yes|-y)\s+)*install|yum\s+install|aptitude\s+install)\s+/;
/*
 * This is fairly ugly because a single RUN could contain multiple install
 * commands, which in turn may install multiple packages, so we've got a
 * 3-level nested array (RUN instruction[] -> install[] -> package[])
 *
 * We also need to account for the multiple ways to split commands, and
 * arbitrary whitespace
 */
function getPackagesFromRunInstructions(runInstructions) {
    return runInstructions.reduce((dockerfilePackages, instruction) => {
        const runDef = "RUN ";
        const commands = instruction.slice(runDef.length).split(/\s?(;|&&)\s?/);
        const installCommands = commands.filter((command) => {
            return installRegex.test(command);
        });
        if (installCommands.length) {
            // Get the packages per install command and flatten them
            installCommands.forEach((command) => {
                const packages = command
                    .replace(installRegex, "")
                    .split(/\s+/)
                    .filter((arg) => arg && !arg.startsWith("-"));
                packages.forEach((pkg) => {
                    dockerfilePackages[pkg] = { instruction };
                });
            });
        }
        return dockerfilePackages;
    }, {});
}
exports.getPackagesFromRunInstructions = getPackagesFromRunInstructions;
function instructionDigest(instruction) {
    return Buffer.from(instruction).toString("base64");
}
exports.instructionDigest = instructionDigest;
function getDockerfileLayers(dockerfilePkgs) {
    return Object.keys(dockerfilePkgs).reduce((res, pkg) => {
        const { instruction } = dockerfilePkgs[pkg];
        res[instructionDigest(instruction)] = { instruction };
        return res;
    }, {});
}
exports.getDockerfileLayers = getDockerfileLayers;
//# sourceMappingURL=instruction-parser.js.map