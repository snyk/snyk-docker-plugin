import * as Debug from "debug";
import * as minimatch from "minimatch";
import * as fspath from "path";
import { fileSync } from "tmp";
import {
  ExtractAction,
  ExtractCallback,
  extractFromTar,
  ExtractProductsByFilename,
} from "./analyzer/image-extractor";
import * as lsu from "./ls-utils";
import { CmdOutput, execute } from "./sub-process";

export { Docker, DockerOptions, STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES };

const debug = Debug("snyk");

const KB = 1024;
const MB = KB * 1024;
const GB = MB * 1024;

const STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES = 3 * GB;

interface DockerOptions {
  host?: string;
  tlsVerify?: string;
  tlsCert?: string;
  tlsCaCert?: string;
  tlsKey?: string;
}

type SaveImageCallback = (err: any, name: string) => void;

interface FilenameProducts {
  [filename: string]: string | Buffer;
}

class Docker {
  public static run(args: string[], options?: DockerOptions) {
    return execute("docker", [...Docker.createOptionsList(options), ...args]);
  }

  private static createOptionsList(options: any) {
    const opts: string[] = [];
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

  private optionsList: string[];
  private extractProductsByFilename: ExtractProductsByFilename;
  private staticScanSizeLimitInBytes: number;

  constructor(
    private targetImage: string,
    options?: DockerOptions,
    staticScanSizeLimit?: number,
  ) {
    this.optionsList = Docker.createOptionsList(options);
    this.extractProductsByFilename = {};
    this.staticScanSizeLimitInBytes =
      staticScanSizeLimit || STATIC_SCAN_MAX_IMAGE_SIZE_IN_BYTES;
  }

  public getTargetImage(): string {
    return this.targetImage;
  }

  /**
   * Runs the command, catching any expected errors and returning them as normal
   * stderr/stdout result.
   */
  public async runSafe(cmd: string, args: string[] = []) {
    try {
      return await this.run(cmd, args);
    } catch (error) {
      const stderr: string = error.stderr;
      if (typeof stderr === "string") {
        if (
          stderr.indexOf("No such file") >= 0 ||
          stderr.indexOf("file not found") >= 0
        ) {
          return { stdout: error.stdout, stderr };
        }
      }
      throw error;
    }
  }

  public GetStaticScanSizeLimit(): number {
    return this.staticScanSizeLimitInBytes;
  }

  public run(cmd: string, args: string[] = []): Promise<CmdOutput> {
    return execute("docker", [
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

  public async inspect(args: string[] = []): Promise<CmdOutput> {
    return await execute("docker", [
      ...this.optionsList,
      "inspect",
      this.targetImage,
      ...args,
    ]);
  }

  public async catSafe(filename: string) {
    return this.runSafe("cat", [filename]);
  }

  public async lsSafe(path: string, recursive?: boolean) {
    let params = "-1ap";
    if (recursive) {
      params += "R";
    }
    return this.runSafe("ls", [params, path]);
  }

  /**
   * Find files on a docker image according to a given list of glob expressions.
   */
  public async findGlobs(
    globs: string[],
    exclusionGlobs: string[] = [],
    path: string = "/",
    recursive: boolean = true,
  ) {
    const res: string[] = [];
    const root = await this.lsSafe(path, recursive).then((output) =>
      lsu.parseLsOutput(output.stdout),
    );

    lsu.iterateFiles(root, (f) => {
      const filepath = fspath.join(f.path, f.name);
      let exclude = false;
      exclusionGlobs.forEach((g) => {
        if (!exclude && minimatch(filepath, g)) {
          exclude = true;
        }
      });
      if (!exclude) {
        globs.forEach((g) => {
          if (minimatch(filepath, g)) {
            res.push(filepath);
          }
        });
      }
    });

    return res;
  }

  /**
   * Returns the size of the specified image, errors are ignored for
   *  backwards compatibility
   * @returns size of image or undefined
   */
  public async sizeSafe(): Promise<number | undefined> {
    try {
      return parseInt(
        (await this.inspect(["--format", "'{{.Size}}'"])).stdout,
        10,
      );
    } catch {
      return undefined;
    }
  }

  public async save(callback: SaveImageCallback): Promise<any> {
    const tmpobj = fileSync({
      mode: 0o644,
      prefix: "docker-",
      postfix: ".image",
      detachDescriptor: true,
    });
    let err = "";

    try {
      await execute("docker", [
        ...this.optionsList,
        "save",
        "-o",
        tmpobj.name,
        this.targetImage,
      ]);
    } catch (error) {
      const stderr: string = error.stderr;
      if (typeof stderr === "string") {
        if (stderr.indexOf("No such image") >= 0) {
          err = `No such image: ${this.targetImage}`;
        } else {
          err = error;
        }
      }
    }

    if (callback) {
      try {
        return await callback(err, tmpobj.name);
      } finally {
        // We don't need the file anymore and could manually call the removeCallback
        tmpobj.removeCallback();
      }
    }
    // if we didn't pass the keep option the file will be deleted on exit
  }

  /**
   * Convenience function to wrap save to tar and extract files from tar
   * @param extractActions array of pattern, callbacks pairs
   * @returns extracted file products
   */
  public async extract(
    extractActions: ExtractAction[],
  ): Promise<ExtractProductsByFilename> {
    return this.save(async (err, imageTarPath) => {
      if (err) {
        throw err;
      }
      return await extractFromTar(imageTarPath, extractActions);
    });
  }

  /**
   * Extract files from image and store their product
   * @param extractActions array of pattern, callbacks pairs
   */
  public async extractAndCache(extractActions: ExtractAction[]): Promise<void> {
    this.extractProductsByFilename = Object.assign(
      this.extractProductsByFilename,
      await this.extract(extractActions),
    );
  }

  /**
   * Attempt to perform a static scan
   * @param extractActions array of pattern, callbacks pairs
   */
  public async scanStaticalyIfNeeded(
    extractActions: ExtractAction[],
  ): Promise<void> {
    const size = await this.sizeSafe();
    if (!size || size > this.GetStaticScanSizeLimit()) {
      return;
    }
    try {
      await this.extractAndCache(extractActions);
    } catch (error) {
      debug(error);
      throw error;
    }
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
  public async getActionProductByFileName(
    filename: string,
    searchActionName: string,
    extractCallback?: ExtractCallback,
  ): Promise<string | Buffer> {
    if (Reflect.has(this.extractProductsByFilename, filename)) {
      const callbackProducts = this.extractProductsByFilename[filename];
      if (Reflect.has(callbackProducts, searchActionName)) {
        return callbackProducts[searchActionName];
      }
    }
    const content = (await this.catSafe(filename)).stdout;
    return extractCallback
      ? extractCallback(Buffer.from(content, "utf8"))
      : content;
  }

  /**
   * Retrieve all filenames with products of the specified action name
   * @param searchActionName name of a search action
   */
  public getActionProducts(searchActionName: string = "txt"): FilenameProducts {
    return Object.keys(this.extractProductsByFilename).reduce(
      (acc: FilenameProducts, file: string) => {
        const val = this.extractProductsByFilename[file][searchActionName];
        return val ? Object.assign(acc, { [file]: val }) : acc;
      },
      {},
    );
  }

  /**
   * Backward compatibility
   * @param filename name of file to retrieve its associated string product
   * @param searchActionName name of a search action
   */
  public async getTextFile(filename: string): Promise<string> {
    const fileProduct = await this.getActionProductByFileName(filename, "txt");
    return fileProduct.toString("utf8");
  }
}
