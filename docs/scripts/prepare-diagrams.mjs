import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const source = new URL('../diagrams/', import.meta.url)
const destination = new URL('../public/diagrams/', import.meta.url)

// Publish only the viewer and downloadable specifications. Review receipts and screenshots stay in Git.
const files = [
  'index.html',
  'runtime-architecture.html',
  'runtime-architecture.en.html',
  'runtime-architecture.json',
  'runtime-architecture.en.json'
]

export function prepareDiagrams() {
  // Read all inputs before replacing the generated directory, so missing inputs fail the build.
  const contents = new Map(files.map(name => [name, readFileSync(new URL(name, source))]))
  const chinese = JSON.parse(contents.get('runtime-architecture.json').toString())
  const english = JSON.parse(contents.get('runtime-architecture.en.json').toString())
  const repository = english.meta.repository
  if (!/^[a-f0-9]{40}$/.test(repository.revision)
      || chinese.meta.repository.revision !== repository.revision
      || chinese.meta.repository.url !== repository.url) {
    throw new Error('Both architecture diagrams must identify the same fixed source revision')
  }

  // This directory is generated and ignored. Replacing it also removes obsolete published files.
  rmSync(destination, { recursive: true, force: true })
  mkdirSync(destination, { recursive: true })
  for (const [name, bytes] of contents) writeFileSync(new URL(name, destination), bytes)
  console.info(`Prepared ${files.length} diagram assets in ${fileURLToPath(destination)}`)
  return repository.revision
}
