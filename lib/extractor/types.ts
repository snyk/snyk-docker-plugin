import { Readable } from "stream";

export type FileContent = string | Buffer;

export type ExtractCallback = (dataStream: Readable) => Promise<FileContent>;

export type FileNameAndContent = Record<string, FileContent>;

export interface ExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface ExtractAction {
  actionName: string; // name, should be unique, for this action
  fileNamePattern: string; // path pattern to look for
  callback?: ExtractCallback; // a callback which processes the file we found and returns some result
}
