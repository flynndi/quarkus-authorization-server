export interface ProjectMetadata {
  groupId: string
  version: string
  quarkusVersion: string
}

export function readProjectMetadata(repoRoot: string): ProjectMetadata

export function replaceProjectPlaceholders(source: string, metadata: ProjectMetadata): string
