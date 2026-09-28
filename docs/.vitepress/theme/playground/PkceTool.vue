<script setup lang="ts">
import { ref, watch } from 'vue'
import { pkceExample, randomValue, s256 } from './oauth-tools.mjs'
import { useToolText } from './useToolText'
import ToolOutput from './ToolOutput.vue'

const { t, errorText } = useToolText()
const verifier = ref('')
const expected = ref('')
const challenge = ref('')
const comparison = ref<boolean | null>(null)
const error = ref('')
const busy = ref(false)
watch([verifier, expected], () => { challenge.value = ''; comparison.value = null; error.value = '' }, { flush: 'sync' })

async function calculate(mode: 'generate' | 'example' | 'check') {
  busy.value = true
  error.value = ''; challenge.value = ''; comparison.value = null
  try {
    if (mode === 'generate') { verifier.value = randomValue(); expected.value = '' }
    if (mode === 'example') { verifier.value = pkceExample.verifier; expected.value = pkceExample.challenge }
    challenge.value = await s256(verifier.value)
    comparison.value = expected.value ? expected.value === challenge.value : null
  } catch (cause) { error.value = errorText(cause) }
  finally { busy.value = false }
}
function clear() { verifier.value = ''; expected.value = ''; error.value = ''; challenge.value = '' }
</script>

<template>
  <div class="pg-tool">
    <div class="pg-toolbar">
      <span class="pg-local">{{ t('BROWSER ONLY', '仅在浏览器内运行') }}</span>
      <button type="button" class="pg-text-button" :disabled="busy" @click="clear">{{ t('Clear', '清空') }}</button>
    </div>
    <form @submit.prevent="calculate('check')">
      <fieldset :disabled="busy">
        <div class="pg-actions">
          <button class="pg-primary" type="button" @click="calculate('generate')">{{ t('Generate a pair', '生成一组 PKCE') }}</button>
          <button class="pg-secondary" type="button" @click="calculate('example')">{{ t('Load RFC 7636 example', '载入 RFC 7636 样例') }}</button>
        </div>
        <label class="pg-field" for="pkce-verifier">code_verifier
          <textarea id="pkce-verifier" v-model="verifier" rows="3" maxlength="128" spellcheck="false" autocomplete="off" autocapitalize="off" aria-describedby="pkce-help" />
        </label>
        <p id="pkce-help" class="pg-help">{{ t('43–128 unreserved characters. The generator uses 32 cryptographically random bytes.', '43–128 位非保留字符。生成器使用 32 字节密码学随机数。') }}</p>
        <label class="pg-field" for="pkce-expected">{{ t('Challenge to compare (optional)', '待比较的 Challenge（可选）') }}
          <input id="pkce-expected" v-model="expected" spellcheck="false" autocomplete="off" autocapitalize="off" maxlength="128" />
        </label>
        <button class="pg-secondary" type="submit">{{ t('Calculate S256', '计算 S256') }}</button>
      </fieldset>
    </form>
    <p v-if="error" class="pg-error" role="alert">{{ error }}</p>
    <div v-if="challenge" class="pg-results">
      <ToolOutput label="code_verifier" :value="verifier" />
      <ToolOutput label="code_challenge" method="S256" :value="challenge" />
      <p v-if="comparison !== null" :class="comparison ? 'pg-success' : 'pg-error'" role="status">
        {{ comparison ? t('The challenges match.', 'Challenge 一致。') : t('The challenges do not match.', 'Challenge 不一致。') }}
      </p>
    </div>
    <p v-else-if="!error" class="pg-empty">{{ t('Generate a new pair or calculate the challenge for your own verifier.', '生成新的一组 PKCE，或输入 verifier 计算其 challenge。') }}</p>
  </div>
</template>
