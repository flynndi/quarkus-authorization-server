import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

function requiredValue(source, pattern, name) {
  const matches = [...source.matchAll(pattern)]
  if (matches.length !== 1 || !matches[0][1].trim()) {
    throw new Error(`Expected one non-empty ${name} in project metadata`)
  }
  return matches[0][1].trim()
}

export function readProjectMetadata(repoRoot) {
  const properties = readFileSync(resolve(repoRoot, 'gradle.properties'), 'utf8')
  const catalog = readFileSync(resolve(repoRoot, 'gradle/libs.versions.toml'), 'utf8')
  const versions = requiredValue(catalog, /^\[versions\][ \t]*\r?\n([\s\S]*?)(?=^\[|(?![\s\S]))/gm, '[versions]')
  const groupId = requiredValue(properties, /^GROUP_ID[ \t]*=[ \t]*(.*)$/gm, 'GROUP_ID')
  const version = requiredValue(properties, /^VERSION[ \t]*=[ \t]*(.*)$/gm, 'VERSION')
  const quarkusVersion = requiredValue(versions, /^quarkus[ \t]*=[ \t]*"([^"]+)"\s*$/gm, 'quarkus version')
  return { groupId, version, quarkusVersion }
}

export function replaceProjectPlaceholders(source, metadata) {
  const values = {
    EXTENSION_GROUP: metadata.groupId,
    EXTENSION_VERSION: metadata.version,
    QUARKUS_VERSION: metadata.quarkusVersion
  }
  return source.replace(/@((?:EXTENSION|QUARKUS)_[A-Z_]+)@/g, (placeholder, key) => {
    if (!Object.hasOwn(values, key)) {
      throw new Error(`Unknown project metadata placeholder: ${placeholder}`)
    }
    return values[key]
  })
}
