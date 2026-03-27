<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content service-modal">
      <div class="service-modal-header">
        <button class="service-modal-close" @click="closeModal">×</button>
        <span>{{ service.icon || '🔨' }}</span>
      </div>
      
      <div class="service-modal-body">
        <h2 class="service-modal-title">{{ service.title }}</h2>
        <div class="service-modal-price">{{ service.price }} ₽/час</div>
        
        <!-- Описание -->
        <div class="service-section">
          <h4>
            <span class="material-symbols-outlined">description</span>
            Описание
          </h4>
          <p class="service-description-text">{{ service.description }}</p>
        </div>
        
        <!-- Характеристики -->
        <div class="service-section">
          <h4>
            <span class="material-symbols-outlined">tune</span>
            Характеристики
          </h4>
          <div class="characteristics-grid">
            <div class="characteristic-item">
              <span class="characteristic-label">Опыт работы</span>
              <span class="characteristic-value">{{ service.experience }} лет</span>
            </div>
            <div class="characteristic-item">
              <span class="characteristic-label">Гарантия</span>
              <span class="characteristic-value">{{ service.guarantee }} год(а)</span>
            </div>
            <div class="characteristic-item">
              <span class="characteristic-label">Срок выполнения</span>
              <span class="characteristic-value">{{ service.completion_time || 'Не указан' }}</span>
            </div>
            <div class="characteristic-item">
              <span class="characteristic-label">Выезд</span>
              <span class="characteristic-value">Бесплатно</span>
            </div>
          </div>
        </div>
        
        <!-- Фото работ -->
        <div class="service-section">
          <h4>
            <span class="material-symbols-outlined">photo_library</span>
            Фото работ
          </h4>
          <div class="photos-grid">
            <div class="photo-item">🔨</div>
            <div class="photo-item">🔧</div>
            <div class="photo-item">⚒️</div>
          </div>
        </div>
        
        <!-- Исполнитель -->
        <div class="service-section">
          <h4>
            <span class="material-symbols-outlined">person</span>
            Исполнитель
          </h4>
          <div class="worker-card">
            <div class="worker-photo">{{ workerInitials }}</div>
            <div class="worker-details">
              <h5>{{ service.worker_name }}</h5>
              <p>Профессионал</p>
              <div class="worker-rating">
                <span class="material-symbols-outlined" style="color: #f59e0b;">star</span>
                <span>{{ service.rating || '0.0' }}</span>
              </div>
            </div>
          </div>
        </div>
        
        <!-- Отзывы -->
        <div class="service-section reviews-section">
          <h4>
            <span class="material-symbols-outlined">reviews</span>
            Последние отзывы
          </h4>
          <div v-if="reviews.length > 0">
            <div v-for="review in reviews" :key="review.id" class="review-item">
              <div class="review-header">
                <span class="review-author">{{ review.author }}</span>
                <span class="review-date">{{ review.date }}</span>
              </div>
              <div class="review-text">{{ review.text }}</div>
            </div>
          </div>
          <p v-else style="color: #64748b; text-align: center; padding: 20px;">
            Пока нет отзывов
          </p>
        </div>
        
        <!-- Кнопки действий -->
        <div class="modal-actions">
          <button class="btn btn-outline" @click="handleContact">Написать</button>
          <button class="btn btn-success" @click="handleOrder">Заказать услугу</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  modelValue: Boolean,
  service: {
    type: Object,
    required: true
  }
})

const emit = defineEmits(['update:modelValue', 'contact', 'order'])

const authStore = useAuthStore()

const workerInitials = computed(() => {
  return props.service.worker_name?.split(' ').map(n => n[0]).join('') || 'И'
})

const reviews = computed(() => {
  // Пока заглушка, потом загрузка из API
  return []
})

function closeModal() {
  emit('update:modelValue', false)
}

function handleContact() {
  emit('contact', props.service)
}

function handleOrder() {
  if (!authStore.isAuthenticated) {
    alert('Для заказа услуги необходимо войти в систему!')
    return
  }
  if (authStore.userRole !== 'customer') {
    alert('Только клиенты могут заказывать услуги!')
    return
  }
  emit('order', props.service)
}
</script>

<style scoped>
/* Стили уже есть в global styles.css */
</style>