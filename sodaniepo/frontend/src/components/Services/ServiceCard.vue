<template>
  <div class="service-card" :class="{ 'ordered': isAlreadyOrdered }">
    <!-- 🔹 Метка если уже заказано -->
    <div v-if="isAlreadyOrdered" class="ordered-badge">
      <span class="icon">✓</span>
      Уже заказано
    </div>
    
    <div class="service-header">
      <h3>{{ service.title }}</h3>
      <div class="rating">
        <span class="star">★</span>
        <span class="rating-value">{{ service.rating?.toFixed(1) || '0.0' }}</span>
      </div>
    </div>
    
    <p class="service-description">{{ service.description }}</p>
    
    <div class="service-meta">
      <span>Исполнитель: {{ service.worker_name }}</span>
      <span>Категория: {{ getCategoryName(service.category) }}</span>
    </div>
    
    <div class="service-footer">
      <span class="service-price">{{ service.price }} ₽/час</span>
      <button 
        class="btn btn-primary" 
        @click="handleOrder"
        :disabled="isAlreadyOrdered"
      >
        {{ isAlreadyOrdered ? 'Заказано' : 'Заказать' }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { ref, onMounted } from 'vue'
import api from '@/api'

const props = defineProps({
  service: Object
})

const emit = defineEmits(['select'])

const router = useRouter()
const authStore = useAuthStore()
const isAlreadyOrdered = ref(false)

// 🔹 Проверяем при загрузке карточки
onMounted(async () => {
  if (authStore.isAuthenticated && authStore.user?.role === 'customer') {
    await checkIfOrdered()
  }
})

async function checkIfOrdered() {
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-customer-orders', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data?.success) {
      // 🔹 Ищем заказ на эту услугу
      const hasOrder = response.data.orders.some(
        o => o.service_id === props.service.id && 
             !['cancelled', 'rejected'].includes(o.status)
      )
      isAlreadyOrdered.value = hasOrder
    }
  } catch (error) {
    console.error('Ошибка проверки заказа:', error)
  }
}

function getCategoryName(category) {
  const names = {
    construction: 'Строительство',
    repair: 'Ремонт',
    electrical: 'Электрика',
    plumbing: 'Сантехника'
  }
  return names[category] || category
}

function handleOrder() {
  if (isAlreadyOrdered.value) {
    alert('⚠️ Вы уже заказывали эту услугу')
    return
  }
  
  if (!authStore.isAuthenticated) {
    alert('Войдите чтобы заказать услугу')
    router.push('/')
    return
  }
  if (authStore.user?.role !== 'customer') {
    alert('Только клиенты могут заказывать услуги')
    return
  }
  
  emit('select', props.service)
}
</script>

<style scoped>
.service-card { 
  border: 1px solid #e2e8f0; 
  border-radius: 12px; 
  padding: 20px; 
  transition: all 0.3s; 
  background: white; 
  position: relative;
}

/* 🔹 Стили для уже заказанной услуги */
.service-card.ordered {
  background: #f8fafc;
  border-color: #cbd5e1;
  opacity: 0.85;
}

.ordered-badge {
  position: absolute;
  top: 12px;
  right: 12px;
  background: #10b981;
  color: white;
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 4px;
}

.ordered-badge .icon {
  font-size: 14px;
}

.service-card:hover { 
  box-shadow: 0 8px 24px rgba(0,0,0,0.12); 
  transform: translateY(-2px); 
}

.service-header { 
  display: flex; 
  justify-content: space-between; 
  align-items: flex-start; 
  margin-bottom: 12px; 
}

.service-header h3 { 
  margin: 0; 
  font-size: 18px; 
  color: #1e293b; 
  flex: 1; 
}

.rating { 
  display: flex; 
  align-items: center; 
  gap: 4px; 
  background: #fef3c7; 
  padding: 4px 8px; 
  border-radius: 4px; 
}

.star { 
  color: #fbbf24; 
  font-size: 16px; 
}

.rating-value { 
  font-weight: 600; 
  color: #92400e; 
  font-size: 14px; 
}

.service-description { 
  color: #64748b; 
  font-size: 14px; 
  line-height: 1.6; 
  margin-bottom: 16px; 
}

.service-meta { 
  display: flex; 
  flex-direction: column; 
  gap: 6px; 
  font-size: 13px; 
  color: #475569; 
  margin-bottom: 16px; 
}

.service-footer { 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  padding-top: 16px; 
  border-top: 1px solid #e2e8f0; 
}

.service-price { 
  font-size: 20px; 
  font-weight: 700; 
  color: #135bec; 
}

.btn { 
  padding: 10px 20px; 
  border-radius: 8px; 
  font-weight: 600; 
  cursor: pointer; 
  transition: all 0.2s; 
  border: none; 
  font-family: 'Manrope', sans-serif; 
  font-size: 14px; 
}

.btn-primary { 
  background: #135bec; 
  color: white; 
}

.btn-primary:hover { 
  background: #0d4bd6; 
  transform: translateY(-2px); 
  box-shadow: 0 4px 12px rgba(19,91,236,0.3); 
}

.btn-primary:disabled {
  background: #94a3b8;
  cursor: not-allowed;
  transform: none;
  box-shadow: none;
}
</style>