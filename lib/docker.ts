import { fileSync } from "tmp";
import {
  ExtractedFiles,
  ExtractFileCallback,
  extractFromTar,
  LookupEntry,
} from "./analyzer/image-extractor";
import { stringToStream } from "./stream-utils";
import { CmdOutput, execute } from "./sub-process";

export { Docker, DockerOptions };

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
  private extractedFiles: ExtractedFiles;

  constructor(private targetImage: string, options?: DockerOptions) {
    this.optionsList = Docker.createOptionsList(options);
    this.extractedFiles = {};
  }

  public getTargetImage(): string {
    return this.targetImage;
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

  public async size(): Promise<number | undefined> {
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
        return callback(err, tmpobj.name);
      } finally {
        // We don't need the file anymore and could manually call the removeCallback
        tmpobj.removeCallback();
      }
    }
    // if we didn't pass the keep option the file will be deleted on exit
  }

  /**
   * Convenience method to wrap save to tar and extract files from tar
   * @param lookups array of pattern, callback pairs
   * @returns extracted file products
   */
  public async extract(lookups: LookupEntry[]): Promise<ExtractedFiles> {
    return this.save(async (err, imageTarPath) => {
      if (err) {
        throw err;
      }
      return await extractFromTar(imageTarPath, lookups);
    });
  }

  /**
   * Extract files from image and store their product
   * @param lookups array of pattern, callback pairs
   * @returns extracted file products
   */
  public async extractAndCache(
    lookups: LookupEntry[],
  ): Promise<ExtractedFiles> {
    return new Promise<ExtractedFiles>((resolve) => {
      this.extract(lookups).then((extractedFiles: ExtractedFiles) => {
        this.extractedFiles = Object.assign(
          this.extractedFiles,
          extractedFiles,
        );
        resolve(this.extractedFiles);
      });
    });
  }

  /**
   * Get file product that was previously retrieved and cached or using runtime method and the specified callback
   * @param filename name of file to retrieve its associated string
   * @param callback optional callback to call when runti,e method is used to retrieve the file
   */
  public async getFile(
    filename: string,
    callback?: ExtractFileCallback,
  ): Promise<string> {
    if (Reflect.has(this.extractedFiles, filename)) {
      return this.extractedFiles[filename];
    } else {
      const content = (await this.catSafe(filename)).stdout;
      return callback ? callback(await stringToStream(content)) : content;
    }
  }
}
