<!-- A small turning ring: something is being worked on. With reduced motion it pulses slowly instead of turning
     (still visibly alive). Decorative: the text next to it says what is happening. -->
<template>
  <span class="spinner" :class="{ big }" aria-hidden="true"></span>
</template>

<script setup>
defineProps({ big: Boolean })
</script>
