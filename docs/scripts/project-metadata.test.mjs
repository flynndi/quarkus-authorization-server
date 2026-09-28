import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { readProjectMetadata, replaceProjectPlaceholders } from './project-metadata.mjs'

function projectFixture(t, properties) {
  const root = mkdtempSync(join(tmpdir(), 'qas-metadata-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  mkdirSync(join(root, 'gradle'))
  writeFileSync(join(root, 'gradle.properties'), properties)
  writeFileSync(join(root, 'gradle/libs.versions.toml'),
    '[versions]\r\nquarkus = "9.8.7"\r\n\r\n[libraries]\r\nquarkus = "not-a-version"\r\n')
  return root
}

test('reads coordinates and the Quarkus version from their canonical files', (t) => {
  const root = projectFixture(t, 'GROUP_ID=org.example\nVERSION=2.0-beta2\n')
  assert.deepEqual(readProjectMetadata(root), {
    groupId: 'org.example', version: '2.0-beta2', quarkusVersion: '9.8.7'
  })
})

test('rejects missing, empty and duplicate release versions', (t) => {
  for (const version of ['', 'VERSION=\n', 'VERSION=1\nVERSION=2\n']) {
    const root = projectFixture(t, `${version}GROUP_ID=org.example\n`)
    assert.throws(() => readProjectMetadata(root), /VERSION/)
  }
})

test('expands prose and code while preserving historical version literals', () => {
  const metadata = { groupId: 'org.example', version: '2.0-beta2', quarkusVersion: '9.8.7' }
  const source = 'Version @EXTENSION_VERSION@; `@EXTENSION_GROUP@:sample:@EXTENSION_VERSION@`\n' +
    '```xml\n<groupId>@EXTENSION_GROUP@</groupId>\n<artifactId>sample</artifactId>\n```\n' +
    'Quarkus @QUARKUS_VERSION@; previously tested with 1.0-SNAPSHOT.'
  assert.equal(replaceProjectPlaceholders(source, metadata),
    'Version 2.0-beta2; `org.example:sample:2.0-beta2`\n' +
    '```xml\n<groupId>org.example</groupId>\n<artifactId>sample</artifactId>\n```\n' +
    'Quarkus 9.8.7; previously tested with 1.0-SNAPSHOT.')
  assert.throws(() => replaceProjectPlaceholders('@EXTENSION_VERSOIN@', metadata), /Unknown/)
})
