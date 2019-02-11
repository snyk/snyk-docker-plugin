import * as subProcess from './sub-process';

export { Docker, DockerOptions};

interface DockerOptions {
    host?: string;
    tlsVerify?: string;
    tlsCert?: string;
    tlsCaCert?: string;
    tlsKey?: string;
}

class Docker {

  private optionsList: string[];

  constructor(
    private targetImage: string,
    options?: DockerOptions,
    ) {
      this.optionsList = this.createOptionsList(options);
  }

  public run(cmd: string, args: string[] = []) {
    return subProcess.execute('docker', [
      ...this.optionsList,
      'run', '--rm', '--entrypoint', '""', '--network', 'none',
      this.targetImage, cmd, ...args,
    ]);
  }

  public async inspect(targetImage: string) {
    return await subProcess.execute('docker',
      [...this.optionsList, 'inspect', targetImage]);
  }

  public async catSafe(filename: string) {
    try {
      return await this.run('cat', [filename]);
    } catch (error) {
      const stderr: string = error.stderr;
      if (typeof stderr === 'string' && stderr.indexOf('No such file') >= 0) {
        return { stdout: '', stderr: '' };
      }
      throw error;
    }
  }

  private createOptionsList(options: any) {
    const opts: string[] = [];
    if (!options) {
      return opts;
    }
    if (options.host) {
      opts.push(`--host=${options.host}`);
    }
    if (options.tlsCert) {
      opts.push(`--tlscert=${options.tlsCert}`);
    }
    if (options.tlsCaCert) {
      opts.push(`--tlscacert=${options.tlsCaCert}`);
    }
    if (options.tlsKey) {
      opts.push(`--tlskey=${options.tlsKey}`);
    }
    if (options.tlsVerify) {
      opts.push(`--tlsverify=${options.tlsVerify}`);
    }
    return opts;
  }
}
