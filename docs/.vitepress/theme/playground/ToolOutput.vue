<script setup lang="ts">
import { ref, watch } from 'vue'
import { useToolText } from './useToolText'

const props = defineProps<{ label: string; value: string; method?: string }>()
const { t } = useToolText()
const status = ref('')
watch(() => props.value, () => { status.value = '' })
async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    status.value = t('Copied', '已复制')
  } catch {
    status.value = t('Select the text to copy manually.', '请手动选择文本复制。')
  }
}
</script>

<template>
  <section class="pg-output" :aria-label="label">
    <div class="pg-output-heading">
      <span><small v-if="method">{{ method }}</small>{{ label }}</span>
      <button type="button" :aria-label="t('Copy ', '复制 ') + label" @click="copy">{{ t('Copy', '复制') }}</button>
    </div>
    <pre tabindex="0" :aria-label="label"><code>{{ value }}</code></pre>
    <p v-if="status" class="pg-copy-status" role="status">{{ status }}</p>
  </section>
</template>
