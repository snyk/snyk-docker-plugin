"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const Debug = require("debug");
const fs_1 = require("fs");
const minimatch = require("minimatch");
const path_1 = require("path");
const tar_stream_1 = require("tar-stream");
const stream_utils_1 = require("../stream-utils");
const debug = Debug("snyk");
/**
 * Extract key files form the specified TAR stream.
 * @param layerTarStream image layer as a Readable TAR stream
 * @param extractActions array of pattern, callbacks pairs
 * @returns extracted file products
 */
function extractFromLayer(layerTarStream, extractActions) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve) => {
            const result = {};
            const layerExtract = tar_stream_1.extract();
            layerExtract.on("entry", (header, stream, next) => tslib_1.__awaiter(this, void 0, void 0, function* () {
                if (header.type === "file" ||
                    header.type === "link" ||
                    header.type === "symlink") {
                    const filename = `/${header.name}`;
                    // convert stream to buffer in order to allow it
                    //  to be processed multiple times by the callback
                    const buffer = yield stream_utils_1.streamToBuffer(stream);
                    for (const extractAction of extractActions) {
                        const callback = extractAction.callback;
                        if (minimatch(filename, extractAction.pattern, { dot: true })) {
                            if (header.type === "file") {
                                // initialize the files associated products dict
                                if (!result[filename]) {
                                    result[filename] = {};
                                }
                                // store the product under the search action name
                                result[filename][extractAction.name] = callback
                                    ? callback(buffer)
                                    : buffer;
                            }
                            else {
                                // target is a link or a symlink
                                debug(`${header.type} '${header.name}' -> '${header.linkname}'`);
                            }
                        }
                    }
                }
                stream.resume(); // auto drain the stream
                next(); // ready for next entry
            }));
            layerExtract.on("finish", () => {
                // all layer level entries read
                resolve(result);
            });
            layerTarStream.pipe(layerExtract);
        });
    });
}
/**
 * Retrieve the products of files content from the specified TAR file.
 * @param imageTarPath path to image file saved in tar format
 * @param extractActions array of pattern, callbacks pairs
 * @returns array of extracted files products sorted by the reverse order of
 *  the layers from last to first
 */
function extractLayersFromTar(imageTarPath, extractActions) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve) => {
            const imageExtract = tar_stream_1.extract();
            const layers = {};
            let layersNames;
            imageExtract.on("entry", (header, stream, next) => tslib_1.__awaiter(this, void 0, void 0, function* () {
                if (header.type === "file") {
                    if (path_1.basename(header.name).endsWith(".tar") &&
                        path_1.basename(header.name) !== "layer.tar") {
                        layers[header.name] = yield extractFromLayer(stream, extractActions);
                    }
                    else if (path_1.basename(header.name) === "layer.tar") {
                        layers[header.name] = yield extractFromLayer(stream, extractActions);
                    }
                    else if (header.name === "manifest.json") {
                        stream_utils_1.streamToString(stream).then((manifestFile) => {
                            const manifest = JSON.parse(manifestFile);
                            layersNames = manifest[0].Layers;
                        });
                    }
                }
                stream.resume(); // auto drain the stream
                next(); // ready for next entry
            }));
            imageExtract.on("finish", () => {
                // reverse layers order from last to first
                // skip (ignore) non-existent layers
                // return the layers content without the name
                resolve(layersNames
                    .reverse()
                    .filter((layersName) => layers[layersName])
                    .map((layerName) => layers[layerName]));
            });
            fs_1.createReadStream(imageTarPath).pipe(imageExtract);
        });
    });
}
/**
 * Extract key files textual content and MD5 sum from the specified TAR file
 * @param imageTarPath path to image file saved in tar format
 * @param extractActions array of pattern, callbacks pairs
 * @returns extracted files products
 */
function extractFromTar(imageTarPath, extractActions) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const layers = yield extractLayersFromTar(imageTarPath, extractActions);
        if (!layers) {
            return {};
        }
        const result = {};
        // reverse layer order from last to first
        for (const layer of layers) {
            // go over extracted files products found in this layer
            for (const filename of Object.keys(layer)) {
                // file was not found
                if (!Reflect.has(result, filename)) {
                    result[filename] = layer[filename];
                }
            }
        }
        return result;
    });
}
exports.extractFromTar = extractFromTar;
//# sourceMappingURL=image-extractor.js.map