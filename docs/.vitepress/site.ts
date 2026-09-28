import { execSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readProjectMetadata } from '../scripts/project-metadata.mjs'

const docsDir = dirname(fileURLToPath(import.meta.url))
export const repoRoot = resolve(docsDir, '../..')

function git(command: string): string {
  return execSync(command, { cwd: repoRoot, encoding: 'utf8' }).trim()
}

export const projectMetadata = readProjectMetadata(repoRoot)

export const siteHost = 'https://authorization-server.dev'
export const githubRepo = 'https://github.com/flynndi/quarkus-authorization-server'
export const extensionVersion = projectMetadata.version
export const quarkusVersion = projectMetadata.quarkusVersion
export const gitCommit = git('git rev-parse --short HEAD')
export const gitCommitFull = git('git rev-parse HEAD')

const previewBranch =
  process.env.WORKERS_CI_BRANCH || process.env.CF_PAGES_BRANCH || process.env.CF_PAGES
export const isPreviewDeploy =
  Boolean(previewBranch) && previewBranch !== 'main' && previewBranch !== '1'

export function githubBlob(path: string, start?: number, end?: number): string {
  const fragment = start ? `#L${start}${end && end !== start ? `-L${end}` : ''}` : ''
  return `${githubRepo}/blob/${gitCommitFull}/${path}${fragment}`
}
