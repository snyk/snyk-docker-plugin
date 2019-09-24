export interface StaticScanningOptions {
  imagePath?: string;
  imageType?: ImageType;
}

export enum ImageType {
  DockerArchive,
}
