"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const dockerfile_ast_1 = require("dockerfile-ast");
const fs = require("fs");
const instruction_parser_1 = require("./instruction-parser");
function readDockerfileAndAnalyse(targetFilePath) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        if (!targetFilePath) {
            return undefined;
        }
        const contents = yield readFile(targetFilePath);
        return analyseDockerfile(contents);
    });
}
exports.readDockerfileAndAnalyse = readDockerfileAndAnalyse;
function analyseDockerfile(contents) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const dockerfile = dockerfile_ast_1.DockerfileParser.parse(contents);
        const from = dockerfile.getFROMs().pop();
        const runInstructions = dockerfile
            .getInstructions()
            .filter((instruction) => {
            return instruction.getInstruction() === "RUN";
        })
            .map((instruction) => instruction.toString());
        const dockerfilePackages = instruction_parser_1.getPackagesFromRunInstructions(runInstructions);
        const dockerfileLayers = instruction_parser_1.getDockerfileLayers(dockerfilePackages);
        let baseImage;
        if (from) {
            const fromVariables = from.getVariables();
            baseImage = from.getImage();
            if (fromVariables) {
                const resolvedVariables = fromVariables.reduce((resolvedVars, variable) => {
                    const line = variable.getRange().start.line;
                    const name = variable.getName();
                    resolvedVars[name] = dockerfile.resolveVariable(name, line);
                    return resolvedVars;
                }, {});
                Object.keys(resolvedVariables).forEach((variable) => {
                    baseImage = baseImage.replace(`\$\{${variable}\}`, resolvedVariables[variable]);
                });
            }
        }
        return {
            baseImage,
            dockerfilePackages,
            dockerfileLayers,
        };
    });
}
exports.analyseDockerfile = analyseDockerfile;
function readFile(path) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            fs.readFile(path, "utf8", (err, data) => {
                return err ? reject(err) : resolve(data);
            });
        });
    });
}
//# sourceMappingURL=docker-file.js.map