<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Заказ услуги</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <div v-if="service" class="service-info">
          <h3>{{ service.title }}</h3>
          <p class="service-price">{{ service.price }} ₽/час</p>
          <p class="service-description">{{ service.description }}</p>
        </div>
        
        <form @submit.prevent="handleSubmit">
          <div class="form-group">
            <label>Ваше имя *</label>
            <input type="text" v-model="form.customer_name" required placeholder="Иван Иванов">
          </div>
          
          <div class="form-group">
            <label>Телефон *</label>
            <input type="tel" v-model="form.customer_phone" required placeholder="+7 (999) 000-00-00">
          </div>
          
          <div class="form-group">
            <label>Адрес *</label>
            <input type="text" v-model="form.customer_address" required placeholder="г. Москва, ул. Примерная, д. 1">
          </div>
          
          <div class="form-group">
            <label>Описание задачи *</label>
            <textarea v-model="form.service_description" required rows="4" placeholder="Опишите что нужно сделать..."></textarea>
          </div>
          
          <div class="form-group">
            <label>Цена (₽)</label>
            <input type="number" v-model.number="form.price" readonly>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading">
            {{ loading ? 'Отправка...' : 'Создать заказ' }}
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
  service: Object
})

const emit = defineEmits(['update:modelValue', 'created'])

const loading = ref(false)

const form = reactive({
  service_title: '',
  service_description: '',
  price: 0,
  customer_name: '',
  customer_phone: '',
  customer_address: '',
  service_id: 0
})

watch(() => props.service, (s) => {
  if (s) {
    form.service_title = s.title
    form.price = s.price
    form.service_id = s.id
  }
}, { immediate: true })

function closeModal() {
  emit('update:modelValue', false)
  resetForm()
}

function resetForm() {
  form.service_description = ''
  form.customer_name = ''
  form.customer_phone = ''
  form.customer_address = ''
}

async function handleSubmit() {
  loading.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.post('/api/create-order', form, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      alert('✅ Заказ создан! Исполнитель свяжется с вами.')
      emit('created')
      closeModal()
    } else {
      const errorMsg = response.data?.message || 'Ошибка создания заказа'
      
      // 🔹 Специальное сообщение для повторного заказа
      if (errorMsg.includes('уже заказывали')) {
        alert('⚠️ Вы уже заказывали эту услугу ранее.\n\nПовторный заказ одной и той же услуги невозможен.')
      } else {
        alert('❌ ' + errorMsg)
      }
    }
  } catch (error) {
    console.error(error)
    
    // 🔹 Обрабатываем ошибку 409 Conflict (повторный заказ)
    if (error.response?.status === 409) {
      alert('⚠️ Вы уже заказывали эту услугу ранее.\n\nПовторный заказ одной и той же услуги невозможен.')
    } else if (error.response?.data?.message) {
      alert('❌ ' + error.response.data.message)
    } else {
      alert('❌ Ошибка подключения к серверу')
    }
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
.service-info { background: #f8fafc; padding: 16px; border-radius: 8px; margin-bottom: 20px; }
.service-info h3 { margin: 0 0 8px 0; color: #1e293b; }
.service-price { font-size: 20px; font-weight: 700; color: #135bec; margin: 8px 0; }
.service-description { color: #64748b; font-size: 14px; line-height: 1.5; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 8px; color: #475569; font-size: 14px; }
.form-group input, .form-group textarea { width: 100%; padding: 12px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; font-family: 'Manrope', sans-serif; }
.form-group input:focus, .form-group textarea:focus { outline: none; border-color: #135bec; box-shadow: 0 0 0 3px rgba(19,91,236,0.1); }
.form-group input[readonly] { background: #f1f5f9; cursor: not-allowed; }
.btn-primary { background: #135bec; color: white; padding: 12px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; }
.btn-primary:disabled { background: #9ca3af; cursor: not-allowed; }
</style>