"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
/**
 * Consume the data from the specified stream into a string
 * @param stream stream to cosume the data from
 * @param encoding encoding to use for convertinf the data to string, default "utf8"
 * @returns string with the data consumed from the specified stream
 */
function streamToString(stream, encoding = "utf8") {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const chunks = [];
        return new Promise((resolve, reject) => {
            stream.on("end", () => {
                resolve(chunks.join(""));
            });
            stream.on("error", reject);
            stream.on("data", (chunk) => {
                chunks.push(chunk.toString(encoding));
            });
        });
    });
}
exports.streamToString = streamToString;
/**
 * Consume the data from the specified stream into a Buffer
 * @param stream stream to cosume the data from
 * @returns Buffer with the data consumed from the specified stream
 */
function streamToBuffer(stream) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const chunks = [];
        return new Promise((resolve, reject) => {
            stream.on("end", () => {
                resolve(Buffer.concat(chunks));
            });
            stream.on("error", reject);
            stream.on("data", (chunk) => {
                chunks.push(Buffer.from(chunk));
            });
        });
    });
}
exports.streamToBuffer = streamToBuffer;
//# sourceMappingURL=stream-utils.js.map