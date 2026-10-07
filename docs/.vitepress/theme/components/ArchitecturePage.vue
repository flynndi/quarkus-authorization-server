<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useData, withBase } from 'vitepress'
import viewerStyles from './architecture-viewer.css?inline'

const { lang, isDark, hash } = useData()
const chinese = computed(() => lang.value === 'zh-CN')
const edition = computed(() => chinese.value ? 'runtime-architecture' : 'runtime-architecture.en')
const revision = __DIAGRAM_REVISION__
const sourceLink = `${__GITHUB_REPO__}/tree/${revision}`
const frame = ref<HTMLIFrameElement>()
const frameSource = ref('')
const diagramVisible = ref(false)
const diagramHash = ref('')
let disconnectViewer = () => {}

function isDiagramHash(value: string) {
  return !value || value === '#diagram' || value === '#VPContent' || value.includes('=')
}

function syncTheme() {
  const doc = frame.value?.contentDocument
  if (!doc?.getElementById('btn-theme')) return
  const theme = isDark.value ? 'dark' : 'light'
  // Use the viewer's own control so its theme and export state stay consistent.
  if (doc.documentElement.getAttribute('data-theme') !== theme) {
    doc.getElementById('btn-theme')!.click()
  }
  const siteStyle = getComputedStyle(document.documentElement)
  doc.documentElement.style.setProperty('--bg', siteStyle.getPropertyValue('--vp-c-bg'))
  doc.documentElement.style.setProperty('--panel', siteStyle.getPropertyValue('--vp-c-bg'))
}

function connectViewer() {
  disconnectViewer()
  const child = frame.value?.contentWindow
  const doc = frame.value?.contentDocument
  if (!child || !doc?.getElementById('focus-chip')) return
  const style = doc.createElement('style')
  style.textContent = viewerStyles
  doc.head.append(style)
  syncTheme()

  const syncFocus = () => {
    diagramHash.value = child.location.hash
    if (!diagramVisible.value) return
    const next = diagramHash.value || '#diagram'
    if (window.location.hash !== next) {
      history.replaceState(history.state, '', next)
      // replaceState emits no event; notify VitePress's read-only hash ref and locale links.
      window.dispatchEvent(new HashChangeEvent('hashchange'))
    }
  }
  const focusObserver = new MutationObserver(syncFocus)
  focusObserver.observe(doc.getElementById('focus-chip')!, { attributes: true, childList: true, subtree: true })
  const themeObserver = new MutationObserver(() => {
    // The viewer's T keyboard shortcut follows the same site-wide preference.
    isDark.value = doc.documentElement.getAttribute('data-theme') === 'dark'
  })
  themeObserver.observe(doc.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
  child.addEventListener('hashchange', syncFocus)
  disconnectViewer = () => {
    focusObserver.disconnect()
    themeObserver.disconnect()
    child.removeEventListener('hashchange', syncFocus)
  }
}

async function restoreView() {
  const current = hash.value
  diagramVisible.value = isDiagramHash(current)
  if (diagramVisible.value) {
    const focus = current.includes('=') ? current : ''
    diagramHash.value = focus
    if (!frameSource.value) {
      frameSource.value = withBase(`/diagrams/${edition.value}.html?theme=${isDark.value ? 'dark' : 'light'}${focus}`)
    } else if (frame.value?.contentWindow && frame.value.contentWindow.location.hash !== focus) {
      frame.value.contentWindow.location.hash = focus
    }
  } else {
    // Reveal Markdown before scrolling to a search result or a shared section link.
    await nextTick()
    let id = current.slice(1)
    try { id = decodeURIComponent(id) } catch { /* A malformed fragment has no matching heading. */ }
    document.getElementById(id)?.scrollIntoView()
  }
}

watch(hash, restoreView)
watch(isDark, () => nextTick(syncTheme))
watch(edition, () => {
  disconnectViewer()
  frameSource.value = ''
  restoreView()
})
onMounted(restoreView)
onBeforeUnmount(() => disconnectViewer())
</script>

<template>
  <div class="architecture-workspace">
    <header class="architecture-bar">
      <p class="architecture-title">{{ chinese ? '架构' : 'Architecture' }}</p>
      <nav :aria-label="chinese ? '架构视图' : 'Architecture views'" class="architecture-views">
        <a :href="diagramHash || '#diagram'" :aria-current="diagramVisible ? 'page' : undefined">
          {{ chinese ? '架构图' : 'Diagram' }}
        </a>
        <a href="#overview" :aria-current="!diagramVisible ? 'page' : undefined">
          {{ chinese ? '文字说明' : 'Overview' }}
        </a>
      </nav>
      <details class="architecture-about">
        <summary>{{ chinese ? '关于' : 'About' }}</summary>
        <div>
          <p>{{ chinese ? '实验性扩展，由社区维护，不由 Quarkus 项目或团队提供和维护。' : 'Experimental extension maintained by community contributors, not by the Quarkus project or team.' }}</p>
          <p>
            {{ chinese ? '图表源码基线：' : 'Diagram source snapshot: ' }}
            <a :href="sourceLink" target="_blank" rel="noopener">{{ revision.slice(0, 7) }}</a>
          </p>
          <p>{{ chinese ? '图表保留该提交的结构与源码链接；当前行为以 Reference 为准。' : 'The diagram preserves this commit’s structure and source links. Consult Reference for current behavior.' }}</p>
          <p><a :href="withBase(`/diagrams/${edition}.json`)" download>{{ chinese ? '下载 JSON 源文件' : 'Download JSON source' }}</a></p>
          <p><a :href="withBase(`/diagrams/?lang=${chinese ? 'zh-CN' : 'en'}&theme=${isDark ? 'dark' : 'light'}${diagramHash}`)" target="_blank" rel="noopener">{{ chinese ? '打开独立查看器 / 导出' : 'Standalone viewer / export' }}</a></p>
        </div>
      </details>
    </header>
    <div v-show="diagramVisible" id="diagram" class="architecture-canvas">
      <iframe
        v-if="frameSource"
        ref="frame"
        :src="frameSource"
        :title="chinese ? 'OAuth2 and OpenID Connect Server Extension 交互运行架构图（实验性）' : 'OAuth2 and OpenID Connect Server Extension interactive runtime architecture (Experimental)'"
        @load="connectViewer"
      />
    </div>
    <article v-show="!diagramVisible" id="overview" class="architecture-copy vp-doc">
      <slot />
    </article>
  </div>
</template>

<style scoped>
.architecture-bar {
  position: sticky;
  top: var(--vp-nav-height);
  z-index: 10;
  display: flex;
  align-items: center;
  gap: 28px;
  height: 56px;
  padding: 0 32px;
  border-bottom: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg);
  font-size: 13px;
}
.architecture-title { font-size: 14px; font-weight: 600; }
.architecture-views { display: flex; align-self: stretch; gap: 24px; }
.architecture-views a { display: flex; align-items: center; border-bottom: 2px solid transparent; color: var(--vp-c-text-2); }
.architecture-views a[aria-current] { color: var(--vp-c-brand-1); border-color: var(--vp-c-brand-1); }
.architecture-about { margin-left: auto; position: relative; color: var(--vp-c-text-2); }
.architecture-about summary { cursor: pointer; }
.architecture-about > div {
  position: absolute;
  right: 0;
  top: 32px;
  width: min(320px, calc(100vw - 32px));
  padding: 20px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  background: var(--vp-c-bg-elv);
  box-shadow: var(--vp-shadow-2);
  line-height: 1.7;
}
.architecture-about p + p { margin-top: 12px; }
.architecture-about a { color: var(--vp-c-brand-1); text-decoration: underline; text-underline-offset: 3px; }
.architecture-bar :is(a, summary):focus-visible { outline: 2px solid var(--vp-c-brand-1); outline-offset: 4px; }
.architecture-canvas { height: calc(100dvh - var(--vp-nav-height) - 56px); min-height: 480px; }
.architecture-canvas iframe { display: block; width: 100%; height: 100%; border: 0; }
.architecture-copy { max-width: 800px; margin: 0 auto; padding: 48px 32px 96px; }
.architecture-copy :deep(:is(h1, h2, h3)) { scroll-margin-top: calc(var(--vp-nav-height) + 80px); }
#overview, #diagram { scroll-margin-top: calc(var(--vp-nav-height) + 56px); }
@media (max-width: 959px) {
  .architecture-bar { top: 0; padding: 0 16px; gap: 20px; }
  .architecture-views { gap: 16px; }
  .architecture-copy { padding: 32px 24px 64px; }
  .architecture-copy :deep(table) { overflow-x: auto; }
}
</style>
