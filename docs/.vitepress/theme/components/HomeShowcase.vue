<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { useData } from 'vitepress'

const { frontmatter } = useData()
const copy = computed(() => frontmatter.value.home)
const repo = __GITHUB_REPO__
const version = __DOCS_VERSION__

// Public credentials from the Client Credentials example.
const request = [
  'curl -u machine-client:machine-secret \\',
  '  -d grant_type=client_credentials \\',
  '  -d scope=message.read \\',
  '  http://127.0.0.1:8080/oauth2/token'
].join('\n')

const copyState = ref<'idle' | 'copied' | 'failed'>('idle')
let resetCopy: ReturnType<typeof setTimeout> | undefined

async function copyRequest() {
  clearTimeout(resetCopy)
  try {
    await navigator.clipboard.writeText(request)
    copyState.value = 'copied'
  } catch {
    copyState.value = 'failed'
  }
  resetCopy = setTimeout(() => {
    copyState.value = 'idle'
  }, 3000)
}

onUnmounted(() => clearTimeout(resetCopy))
</script>

<template>
  <div class="qas-home">
    <section class="qas-hero" aria-labelledby="home-title">
      <div class="qas-hero__intro">
        <p class="qas-eyebrow">
          <span aria-hidden="true" />Quarkus Authorization Server
        </p>
        <h1 id="home-title">
          {{ copy.headline }}<br /><span>{{ copy.emphasis }}</span>
        </h1>
        <p class="qas-hero__lead">{{ copy.lead }}</p>
        <div class="qas-hero__actions">
          <a class="qas-button" :href="copy.startHref">
            {{ copy.start }}<span aria-hidden="true">→</span>
          </a>
          <a class="qas-source" :href="repo">
            {{ copy.source }}<span aria-hidden="true">↗</span>
          </a>
        </div>
        <p class="qas-version"><span>{{ version }}</span>{{ copy.versionNote }}</p>
      </div>

      <figure class="qas-example" aria-labelledby="example-title">
        <figcaption class="qas-example__header">
          <span id="example-title">Client Credentials</span>
          <span class="qas-example__protocol">OAuth 2.0</span>
        </figcaption>
        <div class="qas-example__body">
          <div class="qas-example__label">
            <span>{{ copy.request }}</span>
            <button type="button" @click="copyRequest" :aria-label="copy.copy">
              <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6">
                <rect x="8" y="8" width="12" height="13" rx="2" />
                <path d="M16 8V4a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h4" />
              </svg>
              {{ copyState === 'copied' ? copy.copied : copy.copy }}
            </button>
          </div>
          <pre class="qas-request" tabindex="0" :aria-label="copy.request"><code>{{ request }}</code></pre>
          <div class="qas-example__label qas-example__response">
            <span>{{ copy.response }}</span><span class="qas-http-status">200 OK</span>
          </div>
          <pre class="qas-json" tabindex="0" :aria-label="copy.response"><code>{
  <span>"access_token"</span>: <i>"eyJ…"</i>,
  <span>"token_type"</span>: <i>"Bearer"</i>,
  <span>"expires_in"</span>: <b>120</b>
}</code></pre>
        </div>
        <div class="qas-example__note">
          <span>{{ copy.exampleNote }}</span>
          <a :href="copy.exampleHref">{{ copy.exampleLink }} <span aria-hidden="true">→</span></a>
        </div>
        <p class="qas-copy-status" role="status">
          {{ copyState === 'failed' ? copy.copyFailed : copyState === 'copied' ? copy.copied : '' }}
        </p>
      </figure>
    </section>

    <div class="qas-foundation">
      <p>{{ copy.foundation }}</p>
      <ul aria-label="Quarkus">
        <li>CDI</li>
        <li>HTTP Security</li>
        <li>Vert.x</li>
        <li>quarkus-oidc</li>
      </ul>
    </div>

    <section class="qas-comparison" aria-labelledby="comparison-title">
      <div class="qas-explore__heading">
        <h2 id="comparison-title">{{ copy.comparison.title }}</h2>
        <p>{{ copy.comparison.lead }}</p>
      </div>

      <table class="qas-comparison__table" aria-labelledby="comparison-title">
        <thead>
          <tr>
            <th scope="col">{{ copy.comparison.dimension }}</th>
            <th v-for="product in copy.comparison.products" :key="product.name" scope="col"
              :class="{ 'qas-comparison__featured': product.featured }">
              <span class="qas-comparison__name">{{ product.name }}</span>
              <span class="qas-comparison__kind">{{ product.kind }}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(label, index) in copy.comparison.labels" :key="label">
            <th scope="row">{{ label }}</th>
            <td v-for="product in copy.comparison.products" :key="product.name"
              :class="{ 'qas-comparison__featured': product.featured }">
              {{ product.details[index] }}
            </td>
          </tr>
        </tbody>
        <tfoot>
          <tr>
            <th scope="row">{{ copy.comparison.readMore }}</th>
            <td v-for="product in copy.comparison.products" :key="product.name"
              :class="{ 'qas-comparison__featured': product.featured }">
              <a :href="product.href">{{ product.link }} <span aria-hidden="true">↗</span></a>
            </td>
          </tr>
        </tfoot>
      </table>

      <div class="qas-comparison__cards">
        <article v-for="product in copy.comparison.products" :key="product.name"
          class="qas-comparison__card" :class="{ 'qas-comparison__featured': product.featured }">
          <h3>{{ product.name }}</h3>
          <p class="qas-comparison__kind">{{ product.kind }}</p>
          <dl>
            <div v-for="(label, index) in copy.comparison.labels" :key="label">
              <dt>{{ label }}</dt>
              <dd>{{ product.details[index] }}</dd>
            </div>
          </dl>
          <a :href="product.href">{{ product.link }} <span aria-hidden="true">↗</span></a>
        </article>
      </div>
      <p class="qas-comparison__note">{{ copy.comparison.note }}</p>
    </section>

    <section class="qas-explore" aria-labelledby="explore-title">
      <div class="qas-explore__heading">
        <h2 id="explore-title">{{ copy.pathsTitle }}</h2>
        <p>{{ copy.pathsLead }}</p>
      </div>
      <div class="qas-paths">
        <a v-for="(path, index) in copy.paths" :key="path.href" :href="path.href" class="qas-path">
          <div class="qas-path__meta">
            <span>0{{ index + 1 }} / {{ path.subtitle }}</span>
            <span v-if="path.badge" class="qas-path__badge">{{ path.badge }}</span>
          </div>
          <h3>{{ path.title }}</h3>
          <p>{{ path.description }}</p>
          <span class="qas-path__action">
            {{ path.action }}<span aria-hidden="true">→</span>
          </span>
        </a>
      </div>
    </section>

    <aside class="qas-architecture">
      <p>{{ copy.architecture }}</p>
      <a :href="copy.architectureHref">{{ copy.architectureLink }} <span aria-hidden="true">↗</span></a>
    </aside>
  </div>
</template>
