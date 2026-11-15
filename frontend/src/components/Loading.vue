<!-- "Loading..." while a page or a card waits for its data: always with the spinner. -->
<template>
  <div class="loading" role="status"><Spinner />{{ text || t('common.loading') }}</div>
</template>

<script setup>
import { t } from '../i18n.js'
import Spinner from './Spinner.vue'

defineProps({ text: { type: String, default: '' } })
</script>
