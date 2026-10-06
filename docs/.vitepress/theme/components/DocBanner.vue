<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'

const { lang } = useData()
const zh = computed(() => lang.value.startsWith('zh'))
const repo = __GITHUB_REPO__
const version = __DOCS_VERSION__
const commit = __DOCS_COMMIT__
const commitFull = __DOCS_COMMIT_FULL__
const blob = `${repo}/blob/${commitFull}`
</script>

<template>
  <p class="doc-banner">
    <span class="doc-banner__status">{{ zh ? '实验性 · 社区维护' : 'Experimental · Community-maintained' }}</span>
    <span class="doc-banner__pill">{{ version }}</span>
    <span>
      {{
        zh
          ? '文档对应此版本的仓库源码。'
          : 'These docs describe the source tree for this version.'
      }}
      <a :href="`${blob}`" target="_blank" rel="noreferrer">{{ commit }}</a>
    </span>
  </p>
</template>
