import { Readable } from "stream";

export type ExtractCallback = (dataStream: Readable) => Promise<string>;

export type FileNameAndContent = Record<string, string>;

export interface ExtractedLayers {
  [layerName: string]: FileNameAndContent;
}

export interface ExtractedLayersAndManifest {
  layers: ExtractedLayers[];
  manifest: DockerArchiveManifest;
}

export interface DockerArchiveManifest {
  // Usually points to the json file in the archive that describes how the image was built.
  Config: string;
  RepoTags: string[];
  // The names of the layers in this archive, usually in the format "<sha256ofLayer>.tar".
  Layers: string[];
}

export interface ExtractAction {
  actionName: string; // name, should be unique, for this action
  fileNamePattern: string; // path pattern to look for
  callback?: ExtractCallback; // a callback which processes the file we found and returns some result
}
