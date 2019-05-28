import { fileSync } from "tmp";
import {
  ExtractedImage,
  ExtractedKeyFiles,
  extractImageKeyFiles,
} from "./analyzer/image-extractor";
import { execute } from "./sub-process";

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

  constructor(private targetImage: string, options?: DockerOptions) {
    this.optionsList = Docker.createOptionsList(options);
  }

  public run(cmd: string, args: string[] = []) {
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

  public async inspect(targetImage: string) {
    return await execute("docker", [
      ...this.optionsList,
      "inspect",
      targetImage,
    ]);
  }

  public async catSafe(filename: string) {
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
   * Analyze and return key files textual content and MD5 sum.
   * @param imageTarPath path to image file saved in tar format
   * @param txtPatterns list of plain text key files paths patterns to extract and return as strings
   * @param md5Patterns list of binary key files paths patterns to extract and return their MD5 sum
   * @returns key files textual content and MD5 sum
   */
  public async analyze(
    imageTarPath: string,
    txtPatterns: string[],
    md5Patterns: string[] = [],
  ) {
    const result: ExtractedKeyFiles = { txt: {}, md5: {} };

    const extracted: ExtractedImage = await extractImageKeyFiles(
      imageTarPath,
      txtPatterns,
      md5Patterns,
    );

    const manifest = JSON.parse(extracted.manifest);
    const layersNames: string[] = manifest[0].Layers;

    if (extracted.layers) {
      // reverse layer order from last to first
      for (const layerName of layersNames.reverse()) {
        // files found for this layer
        if (layerName in extracted.layers) {
          // go over plain text files found in this layer
          for (const filename of Object.keys(extracted.layers[layerName].txt)) {
            // file was not found in previous layer
            if (!Reflect.has(result.txt, filename)) {
              result.txt[filename] = extracted.layers[layerName].txt[filename];
            }
          }
          // go over MD5 sums found in this layer
          for (const filename of Object.keys(extracted.layers[layerName].md5)) {
            // file was not found in previous layer
            if (!Reflect.has(result.md5, filename)) {
              result.md5[filename] = extracted.layers[layerName].md5[filename];
            }
          }
        }
      }
    }
    return result;
  }

  /**
   * Saves the docker image as a TAR file to a temporary location and extract
   * the specified files from it.
   * @param txtPatterns list of plain text key files paths patterns to extract and return as strings
   * @param md5Patterns list of binary key files paths patterns to extract and return their MD5 sum
   * @return list of plain text files and list of MD5 sums
   */
  public async extract(
    txtPatterns: string[],
    md5Patterns: string[] = [],
  ): Promise<ExtractedKeyFiles> {
    return this.save(async (err, imageTarPath) => {
      if (err) {
        throw err;
      }
      return await this.analyze(imageTarPath, txtPatterns, md5Patterns);
    });
  }
}
