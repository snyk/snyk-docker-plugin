"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
function detect(docker, useSkopeo = false) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        try {
            const info = yield docker.inspect([], useSkopeo);
            return JSON.parse(info.stdout)[0];
        }
        catch (error) {
            if (error.stderr.includes("No such object")) {
                throw new Error(`Docker error: image was not found locally: ${docker.getTargetImage()}`);
            }
            throw new Error(`Docker error: ${error.stderr}`);
        }
    });
}
exports.detect = detect;
//# sourceMappingURL=image-inspector.js.map