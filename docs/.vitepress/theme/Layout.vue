<script setup lang="ts">
import DefaultTheme from 'vitepress/theme'
import DocBanner from './components/DocBanner.vue'
import HomeShowcase from './components/HomeShowcase.vue'

const { Layout } = DefaultTheme
</script>

<template>
  <Layout>
    <template #home-hero-before>
      <HomeShowcase />
    </template>
    <template #doc-before>
      <DocBanner />
    </template>
  </Layout>
</template>
