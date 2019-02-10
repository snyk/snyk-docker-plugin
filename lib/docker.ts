import * as subProcess from './sub-process';

export { Docker };

class Docker {
  constructor(private targetImage: string) {
  }

  public run(cmd: string, args: string[] = []) {
    return subProcess.execute('docker', [
      'run', '--rm', '--entrypoint', '""', '--network', 'none',
      this.targetImage, cmd, ...args,
    ]);
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
}
