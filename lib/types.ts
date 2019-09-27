export interface StaticAnalysisOptions {
  imagePath?: string;
  imageType?: ImageType;
}

export enum ImageType {
  DockerArchive,
}
