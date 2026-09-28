<script setup>
import { onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { authority, manager, user } from "../client";
const route = useRoute();
const router = useRouter();
const pending = ref(route.path === "/callback");
const error = ref("");
const resource = ref(null);
const resourceError = ref("");
const loading = ref(false);
onMounted(async () => {
  if (route.path !== "/callback") return;
  try {
    user.value = await manager.signinRedirectCallback();
  } catch (failure) {
    error.value = failure.error ? `${failure.error}: ${failure.message}` : failure.message;
  } finally {
    pending.value = false;
    await router.replace("/result");
  }
});
async function callResource() {
  resource.value = null;
  resourceError.value = "";
  loading.value = true;
  try {
    // Deliberately omit the login cookie: the resource server must authenticate the access token.
    const response = await fetch(`${authority}/api/messages`, {
      credentials: "omit",
      headers: { Authorization: `Bearer ${user.value.access_token}` },
    });
    if (!response.ok)
      throw new Error(
        `资源服务器返回 HTTP ${response.status}；请检查 message.read scope 和令牌有效期。`,
      );
    resource.value = await response.json();
  } catch (failure) {
    resourceError.value = failure.message;
  } finally {
    loading.value = false;
  }
}
async function logout() {
  error.value = "";
  try {
    await manager.signoutRedirect();
  } catch (failure) {
    error.value = failure.message;
  }
}
</script>
<template>
  <section class="card">
    <p class="eyebrow">04 / RESOURCE SERVER</p>
    <h2>
      {{ pending ? "正在完成授权…" : user ? "授权完成" : "尚未获得访问令牌" }}
    </h2>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <template v-if="user">
      <div class="success">✓ 已完成 Authorization Code + PKCE</div>
      <dl class="facts">
        <div>
          <dt>用户</dt>
          <dd>{{ user.profile.sub }}</dd>
        </div>
        <div>
          <dt>批准的 scope</dt>
          <dd>{{ user.scope }}</dd>
        </div>
        <div>
          <dt>Token 类型</dt>
          <dd>{{ user.token_type }}</dd>
        </div>
        <div>
          <dt>到期时间</dt>
          <dd>{{ new Date(user.expires_at * 1000).toLocaleTimeString() }}</dd>
        </div>
      </dl>
      <button class="primary" :disabled="loading" @click="callResource">
        {{ loading ? "正在请求…" : "调用受保护 API" }}
      </button>
      <p v-if="resourceError" class="error" role="alert">{{ resourceError }}</p>
      <pre v-if="resource" class="resource-result">{{
        JSON.stringify(resource, null, 2)
      }}</pre>
      <details>
        <summary>查看令牌与用户声明</summary>
        <p class="hint">仅用于本地演示，请勿分享令牌。</p>
        <label class="field"
          >Access token<textarea readonly :value="user.access_token" rows="4" />
        </label>
        <pre>{{ JSON.stringify(user.profile, null, 2) }}</pre>
      </details>
      <button class="secondary" @click="logout">退出登录并清除页面令牌</button>
      <p class="hint">
        退出会清除登录 Cookie；已签发的 access token 仍按自己的有效期生效。
      </p>
    </template>
    <p v-else-if="!pending && !error" class="muted">
      页面刷新会清除内存中的令牌。你可以重新发起授权，复用仍有效的登录状态。
    </p>
    <RouterLink class="text-link" to="/">返回客户端首页</RouterLink>
  </section>
</template>
