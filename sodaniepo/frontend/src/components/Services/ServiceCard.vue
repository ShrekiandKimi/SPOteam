<template>
  <div class="service-card" @click="$emit('select', service)">
    <div class="service-image">{{ service.icon || '🔨' }}</div>
    <div class="service-info">
      <div class="service-price">{{ service.price }} ₽/час</div>
      <h3 class="service-title">{{ service.title }}</h3>
      <p class="service-description">{{ service.description }}</p>
      <div class="service-meta">
        <div class="worker-info">
          <div class="worker-avatar">{{ workerInitial }}</div>
          <span class="worker-name">{{ service.worker_name || 'Исполнитель' }}</span>
        </div>
        <div class="service-rating">
          <span class="material-symbols-outlined" style="font-size: 18px;">star</span>
          {{ service.rating || '0.0' }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  service: {
    type: Object,
    required: true
  }
})

defineEmits(['select'])

const workerInitial = computed(() => 
  props.service.worker_name?.charAt(0).toUpperCase() || 'И'
)
</script>

<style scoped>
/* Стили уже есть в global CSS */
</style>