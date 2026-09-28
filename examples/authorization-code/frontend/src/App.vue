<script setup>
import { useRoute } from "vue-router";
const route = useRoute();
const steps = [
  { name: "发起授权", paths: ["/"] },
  { name: "授权服务器登录", paths: [] },
  { name: "授权服务器确认范围", paths: [] },
  { name: "访问资源", paths: ["/callback", "/result"] },
];
</script>

<template>
  <div class="shell">
    <header>
      <RouterLink class="brand" to="/"
        ><span class="mark">Q</span
        ><span>Quarkus <strong>Authorization</strong></span></RouterLink
      ><span class="badge">Vue 3 · PKCE</span>
    </header>
    <div class="layout">
      <aside>
        <p class="eyebrow">AUTHORIZATION CODE</p>
        <h1>一次授权，<br />看清完整流程。</h1>
        <p class="muted">
          浏览器客户端与 Quarkus 后端，完成从用户登录到 API 访问的全过程。
        </p>
        <ol class="steps">
          <li
            v-for="(step, index) in steps"
            :key="step.name"
            :class="{ active: step.paths.includes(route.path) }"
          >
            <span>{{ index + 1 }}</span
            >{{ step.name }}
          </li>
        </ol>
        <div class="aside-note">
          登录和授权确认在授权服务器完成；此页面是独立的 Vue 业务客户端。
        </div>
      </aside>
      <main><RouterView /></main>
    </div>
    <footer>本地集成演示 <span>Authorization Code + S256 PKCE</span></footer>
  </div>
</template>
