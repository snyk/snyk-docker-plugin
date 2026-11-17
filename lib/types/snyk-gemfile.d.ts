declare module "@snyk/gemfile" {
  export function interpret(
    gemfile: string,
    extractMeta?: boolean,
  ): Record<string, unknown>;
  export function parse(
    filename?: string,
    extractMeta?: boolean,
  ): Promise<Record<string, unknown>>;
  export function parseSync(
    filename?: string,
    extractMeta?: boolean,
  ): Record<string, unknown>;
}
