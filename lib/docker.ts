import { fileSync } from "tmp";
import { debug } from "util";
import {
  extractFromTar,
  SearchAction,
  SearchActionCallback,
  SearchActionProducts,
} from "./analyzer/image-extractor";
import { CmdOutput, execute } from "./sub-process";

export { Docker, DockerOptions, STATIC_SCAN_MAX_IMAGE_SIZE_IN_KB };

const KB = 1024;
const MB = KB * 1024;
const GB = MB * 1024;

const STATIC_SCAN_MAX_IMAGE_SIZE_IN_KB = 3 * GB;

interface DockerOptions {
  host?: string;
  tlsVerify?: string;
  tlsCert?: string;
  tlsCaCert?: string;
  tlsKey?: string;
}

type SaveImageCallback = (err: any, name: string) => void;

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
  private searchActionProducts: SearchActionProducts;
  private staticScanSizeLimit: number;

  constructor(
    private targetImage: string,
    options?: DockerOptions,
    staticScanSizeLimit?: number,
  ) {
    this.optionsList = Docker.createOptionsList(options);
    this.searchActionProducts = {};
    this.staticScanSizeLimit =
      staticScanSizeLimit || STATIC_SCAN_MAX_IMAGE_SIZE_IN_KB;
  }

  public getTargetImage(): string {
    return this.targetImage;
  }

  public GetStaticScanSizeLimit(): number {
    return this.staticScanSizeLimit;
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

  public async catSafe(filename: string): Promise<CmdOutput> {
    try {
      return await this.run("cat", [filename]);
    } catch (error) {
      const stderr: string = error.stderr;
      if (typeof stderr === "string") {
        if (
          stderr.indexOf("No such file") >= 0 ||
          stderr.indexOf("file not found") >= 0
        ) {
          return { stdout: "", stderr: "" };
        }
      }
      throw error;
    }
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
   * @param searchActions array of pattern, callbacks pairs
   * @returns extracted file products
   */
  public async extract(
    searchActions: SearchAction[],
  ): Promise<SearchActionProducts> {
    return this.save(async (err, imageTarPath) => {
      if (err) {
        throw err;
      }
      return await extractFromTar(imageTarPath, searchActions);
    });
  }

  /**
   * Extract files from image and store their product
   * @param searchActions array of pattern, callbacks pairs
   * @returns extracted file products
   */
  public async extractAndCache(
    searchActions: SearchAction[],
  ): Promise<SearchActionProducts> {
    try {
      this.searchActionProducts = Object.assign(
        this.searchActionProducts,
        await this.extract(searchActions),
      );
      return this.searchActionProducts;
    } catch (error) {
      debug(error);
      return {};
    }
  }

  /**
   * Attempt to perform a static scan
   * @param searchActions
   */
  public async maybeStaticScan(searchActions: SearchAction[]) {
    const size = await this.sizeSafe();
    if (!size || size > this.GetStaticScanSizeLimit()) {
      return {};
    }
    return await this.extractAndCache(searchActions);
  }

  /**
   * Get file product that was previously retrieved and cached or by using
   *  runtime method after applying the specified callback
   * @param filename name of file to retrieve its associated string product
   * @param callbacks optional array of callbacks to call when runtime method
   *  is used to retrieve the file
   * @returns map of file products by callback name
   */
  public async getFilesProducts(
    filename: string,
    callbacks?: SearchActionCallback[],
  ): Promise<{ [key: string]: string | Buffer }> {
    if (Reflect.has(this.searchActionProducts, filename)) {
      return this.searchActionProducts[filename];
    }
    const content = (await this.catSafe(filename)).stdout;
    if (!callbacks) {
      return { "": content };
    }
    const result: { [key: string]: string | Buffer } = {};
    for (const callback of callbacks) {
      result[callback.name] = callback.call(Buffer.from(content, "utf8"));
    }
    return result;
  }

  /**
   * Convenience function the single product of a single file
   * @param filename name of file to retrieve its associated single product
   * @param callback optional callback to call when runtime method is used
   *  to retrieve the file
   * @returns file product, the only one
   */
  public async getFileProduct(
    filename: string,
    callback?: SearchActionCallback,
  ): Promise<string> {
    const result = await this.getFilesProducts(
      filename,
      callback ? [callback] : undefined,
    );
    const length = Object.keys(result).length;
    if (length > 1) {
      throw new Error(`File product ambiguity, ${length}`);
    }
    // return the first and only product of the file
    return result[Object.keys(result)[0]].toString("utf8");
  }
}
