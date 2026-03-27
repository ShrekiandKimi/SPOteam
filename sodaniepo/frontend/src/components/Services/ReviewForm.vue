<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Оставить отзыв</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <div v-if="order" class="order-info">
          <h3>{{ order.service_title }}</h3>
          <p>Исполнитель: {{ order.worker_name }}</p>
        </div>
        
        <form @submit.prevent="handleSubmit">
          <div class="form-group">
            <label>Оценка *</label>
            <div class="rating-input">
              <span 
                v-for="star in 5" 
                :key="star"
                :class="['star', { active: star <= form.rating }]"
                @click="form.rating = star"
              >
                ★
              </span>
            </div>
          </div>
          
          <div class="form-group">
            <label>Комментарий</label>
            <textarea v-model="form.comment" rows="4" placeholder="Расскажите о вашем опыте работы..."></textarea>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading || form.rating === 0">
            {{ loading ? 'Отправка...' : 'Отправить отзыв' }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref, watch } from 'vue'
import api from '@/api'

const props = defineProps({
  modelValue: Boolean,
  order: Object
})

const emit = defineEmits(['update:modelValue', 'created'])

const loading = ref(false)

const form = reactive({
  order_id: 0,
  rating: 0,
  comment: ''
})

watch(() => props.order, (o) => {
  if (o) {
    form.order_id = o.id
  }
}, { immediate: true })

function closeModal() {
  emit('update:modelValue', false)
  form.rating = 0
  form.comment = ''
}

async function handleSubmit() {
  if (form.rating === 0) {
    alert('Поставьте оценку')
    return
  }
  
  loading.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.post('/api/create-review', form, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      alert('Спасибо за отзыв!')
      emit('created')
      closeModal()
    } else {
      alert('Ошибка: ' + response.data.message)
    }
  } catch (error) {
    console.error(error)
    alert('Ошибка подключения к серверу')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); z-index: 1000; align-items: center; justify-content: center; }
.modal.active { display: flex; }
.modal-content { background: white; border-radius: 12px; width: 90%; max-width: 500px; max-height: 90vh; overflow-y: auto; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 20px 24px; border-bottom: 1px solid #e2e8f0; }
.modal-header h2 { margin: 0; font-size: 1.25rem; color: #1e293b; }
.modal-close { background: none; border: none; font-size: 28px; cursor: pointer; color: #64748b; }
.modal-body { padding: 24px; }
.order-info { background: #f8fafc; padding: 16px; border-radius: 8px; margin-bottom: 20px; }
.order-info h3 { margin: 0 0 8px 0; color: #1e293b; }
.order-info p { margin: 0; color: #64748b; font-size: 14px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 8px; color: #475569; font-size: 14px; }
.rating-input { display: flex; gap: 8px; font-size: 32px; cursor: pointer; }
.star { color: #e2e8f0; transition: color 0.2s; }
.star.active, .star:hover { color: #fbbf24; }
.form-group textarea { width: 100%; padding: 12px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; font-family: 'Manrope', sans-serif; resize: vertical; }
.form-group textarea:focus { outline: none; border-color: #135bec; box-shadow: 0 0 0 3px rgba(19,91,236,0.1); }
.btn-primary { background: #135bec; color: white; padding: 12px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; }
.btn-primary:disabled { background: #9ca3af; cursor: not-allowed; }
</style>