<script setup>
import { ref } from "vue";
import { authority, clientId, manager, user } from "../client";
const selected = ref(["profile", "message.read"]);
const pending = ref(false);
const error = ref("");
async function authorize() {
  pending.value = true;
  error.value = "";
  try {
    await manager.clearStaleState();
    await manager.signinRedirect({
      scope: ["openid", ...selected.value].join(" "),
    });
  } catch (failure) {
    error.value = failure.message;
    pending.value = false;
  }
}
</script>
<template>
  <section class="card">
    <p class="eyebrow">01 / CLIENT</p>
    <h2>开始一次授权</h2>
    <p class="muted">选择应用需要的访问范围，然后前往授权服务器登录。</p>
    <p class="hint">演示账号：resource-owner / resource-owner-password</p>
    <dl class="facts">
      <div>
        <dt>授权服务器</dt>
        <dd>{{ authority }}</dd>
      </div>
      <div>
        <dt>客户端</dt>
        <dd>{{ clientId }}</dd>
      </div>
      <div>
        <dt>客户端类型</dt>
        <dd>Public client <span class="inline-tag">无客户端密钥</span></dd>
      </div>
    </dl>
    <fieldset>
      <legend>申请的 scope</legend>
      <label class="choice"
        ><input type="checkbox" checked disabled /><span
          ><strong>openid</strong><small>确认登录用户的身份</small></span
        ></label
      >
      <label class="choice"
        ><input v-model="selected" type="checkbox" value="profile" /><span
          ><strong>profile</strong><small>申请用户资料</small></span
        ></label
      >
      <label class="choice"
        ><input v-model="selected" type="checkbox" value="message.read" /><span
          ><strong>message.read</strong><small>读取示例消息接口</small></span
        ></label
      >
    </fieldset>
    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <button class="primary" :disabled="pending" @click="authorize">
      {{ pending ? "正在跳转…" : "开始授权 →" }}
    </button>
    <RouterLink v-if="user" class="text-link" to="/result"
      >查看当前授权结果</RouterLink
    >
    <p class="hint">
      PKCE 和 state 由 OIDC 客户端库管理。访问令牌只保存在当前页面内存中。
    </p>
  </section>
</template>
