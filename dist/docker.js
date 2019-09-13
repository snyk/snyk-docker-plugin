"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const tslib_1 = require("tslib");
const Debug = require("debug");
const tmp_1 = require("tmp");
const image_extractor_1 = require("./analyzer/image-extractor");
const sub_process_1 = require("./sub-process");
const debug = Debug("snyk");
const KB = 1024;
const MB = KB * 1024;
const GB = MB * 1024;
const STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES = 3 * GB;
exports.STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES = STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES;
class Docker {
    constructor(targetImage, options, staticScanSizeLimit) {
        this.targetImage = targetImage;
        this.optionsList = Docker.createOptionsList(options);
        this.extractProductsByFilename = {};
        this.staticScanSizeLimitInBytes =
            staticScanSizeLimit || STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES;
    }
    static run(args, options) {
        return sub_process_1.execute("docker", [...Docker.createOptionsList(options), ...args]);
    }
    static createOptionsList(options) {
        const opts = [];
        if (!options) {
            return opts;
        }
        if (options.host) {
            opts.push(`--host=${options.host}`);
        }
        if (options.tlscert) {
            opts.push(`--tlscert=${options.tlscert}`);
        }
        if (options.tlscacert) {
            opts.push(`--tlscacert=${options.tlscacert}`);
        }
        if (options.tlskey) {
            opts.push(`--tlskey=${options.tlskey}`);
        }
        if (options.tlsverify) {
            opts.push(`--tlsverify=${options.tlsverify}`);
        }
        return opts;
    }
    getTargetImage() {
        return this.targetImage;
    }
    GetStaticScanSizeLimit() {
        return this.staticScanSizeLimitInBytes;
    }
    run(cmd, args = []) {
        return sub_process_1.execute("docker", [
            ...this.optionsList,
            "run",
            "--rm",
            "--entrypoint",
            '""',
            "--network",
            "none",
            this.targetImage,
            cmd,
            ...args,
        ]);
    }
    inspect(args = [], useSkopeo = false) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (useSkopeo) {
                return yield sub_process_1.execute("skopeo", [
                    ...this.optionsList,
                    "inspect",
                    this.targetImage,
                    ...args,
                ]);
            }
            return yield sub_process_1.execute("docker", [
                ...this.optionsList,
                "inspect",
                this.targetImage,
                ...args,
            ]);
        });
    }
    catSafe(filename) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            try {
                return yield this.run("cat", [filename]);
            }
            catch (error) {
                const stderr = error.stderr;
                if (typeof stderr === "string") {
                    if (stderr.indexOf("No such file") >= 0 ||
                        stderr.indexOf("file not found") >= 0) {
                        return { stdout: "", stderr: "" };
                    }
                }
                throw error;
            }
        });
    }
    /**
     * Returns the size of the specified image, errors are ignored for
     *  backwards compatibility
     * @returns size of image or undefined
     */
    sizeSafe() {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            try {
                return parseInt((yield this.inspect(["--format", "'{{.Size}}'"])).stdout, 10);
            }
            catch (_a) {
                return undefined;
            }
        });
    }
    save(callback) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const tmpobj = tmp_1.fileSync({
                mode: 0o644,
                prefix: "docker-",
                postfix: ".image",
                detachDescriptor: true,
            });
            let err = "";
            try {
                yield sub_process_1.execute("docker", [
                    ...this.optionsList,
                    "save",
                    "-o",
                    tmpobj.name,
                    this.targetImage,
                ]);
            }
            catch (error) {
                const stderr = error.stderr;
                if (typeof stderr === "string") {
                    if (stderr.indexOf("No such image") >= 0) {
                        err = `No such image: ${this.targetImage}`;
                    }
                    else {
                        err = error;
                    }
                }
            }
            if (callback) {
                try {
                    return yield callback(err, tmpobj.name);
                }
                finally {
                    // We don't need the file anymore and could manually call the removeCallback
                    tmpobj.removeCallback();
                }
            }
            // if we didn't pass the keep option the file will be deleted on exit
        });
    }
    /**
     * Convenience function to wrap save to tar and extract files from tar
     * @param extractActions array of pattern, callbacks pairs
     * @returns extracted file products
     */
    extract(extractActions, dockerArchivePath) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (dockerArchivePath !== undefined) {
                return yield image_extractor_1.extractFromTar(dockerArchivePath, extractActions);
            }
            return this.save((err, imageTarPath) => tslib_1.__awaiter(this, void 0, void 0, function* () {
                if (err) {
                    throw err;
                }
                return yield image_extractor_1.extractFromTar(imageTarPath, extractActions);
            }));
        });
    }
    /**
     * Extract files from image and store their product
     * @param extractActions array of pattern, callbacks pairs
     */
    extractAndCache(extractActions, dockerArchivePath) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            this.extractProductsByFilename = Object.assign(this.extractProductsByFilename, yield this.extract(extractActions, dockerArchivePath));
        });
    }
    /**
     * Attempt to perform a static scan
     * @param extractActions array of pattern, callbacks pairs
     */
    scanStaticalyIfNeeded(extractActions, dockerArchivePath) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (dockerArchivePath === undefined) {
                const size = yield this.sizeSafe();
                if (!size || size > this.GetStaticScanSizeLimit()) {
                    return;
                }
            }
            try {
                yield this.extractAndCache(extractActions, dockerArchivePath);
            }
            catch (error) {
                debug(error);
                throw error;
            }
        });
    }
    /**
     * Get file product that was previously retrieved and cached or by using
     *  runtime method after applying the specified callback
     * @param filename name of file to retrieve its associated string product
     * @param searchActionName name of a search action
     * @param callbacks optional array of callbacks to call when runtime method
     *  is used to retrieve the file
     * @returns map of file products by callback name
     */
    getActionProductByFileName(filename, searchActionName, extractCallback) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            if (Reflect.has(this.extractProductsByFilename, filename)) {
                const callbackProducts = this.extractProductsByFilename[filename];
                if (Reflect.has(callbackProducts, searchActionName)) {
                    return callbackProducts[searchActionName];
                }
            }
            const content = (yield this.catSafe(filename)).stdout;
            return extractCallback
                ? extractCallback(Buffer.from(content, "utf8"))
                : content;
        });
    }
    /**
     * Retrieve all filenames with products of the specified action name
     * @param searchActionName name of a search action
     */
    getActionProducts(searchActionName = "txt") {
        return Object.keys(this.extractProductsByFilename).reduce((acc, file) => {
            const val = this.extractProductsByFilename[file][searchActionName];
            return val ? Object.assign(acc, { [file]: val }) : acc;
        }, {});
    }
    /**
     * Backward compatibility
     * @param filename name of file to retrieve its associated string product
     * @param searchActionName name of a search action
     */
    getTextFile(filename) {
        return tslib_1.__awaiter(this, void 0, void 0, function* () {
            const fileProduct = yield this.getActionProductByFileName(filename, "txt");
            return fileProduct.toString("utf8");
        });
    }
}
exports.Docker = Docker;
//# sourceMappingURL=docker.js.map