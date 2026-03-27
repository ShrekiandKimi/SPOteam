<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>🔨 Добавить услугу</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      
      <div class="modal-body">
        <form @submit.prevent="handleSubmit">
          <div class="form-group">
            <label>Название услуги *</label>
            <input 
              type="text" 
              v-model="form.title" 
              required 
              placeholder="Например: Строительство стен и перегородок"
            >
          </div>

          <div class="form-group">
            <label>Категория *</label>
            <select v-model="form.category" required>
              <option value="">Выберите категорию</option>
              <option value="construction">Строительство</option>
              <option value="repair">Ремонт</option>
              <option value="electrical">Электрика</option>
              <option value="plumbing">Сантехника</option>
            </select>
          </div>

          <div class="form-group">
            <label>Цена (₽/час) *</label>
            <input 
              type="number" 
              v-model.number="form.price" 
              required 
              min="100"
              placeholder="1500"
            >
          </div>

          <div class="form-group">
            <label>Описание *</label>
            <textarea 
              v-model="form.description" 
              required 
              rows="4"
              placeholder="Опишите вашу услугу подробно..."
            ></textarea>
          </div>

          <div class="form-group">
            <label>Опыт работы (лет)</label>
            <input 
              type="number" 
              v-model.number="form.experience" 
              min="0"
              placeholder="5"
            >
          </div>

          <div class="form-group">
            <label>Гарантия (лет)</label>
            <input 
              type="number" 
              v-model.number="form.guarantee" 
              min="0"
              placeholder="1"
            >
          </div>

          <div class="form-group">
            <label>Срок выполнения</label>
            <input 
              type="text" 
              v-model="form.completion_time" 
              placeholder="Например: от 3 дней"
            >
          </div>

          <div class="form-group">
            <label>Telegram</label>
            <input 
              type="text" 
              v-model="form.telegram" 
              placeholder="@username"
            >
          </div>

          <div class="form-group">
            <label>MAX (телефон)</label>
            <input 
              type="text" 
              v-model="form.max" 
              placeholder="+7 (999) 123-45-67"
            >
          </div>

          <div class="modal-actions">
            <button type="button" class="btn btn-outline" @click="closeModal">Отмена</button>
            <button type="submit" class="btn btn-success" :disabled="loading">
              {{ loading ? '⏳ Создание...' : 'Создать услугу' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import api from '@/api'

const props = defineProps({
  modelValue: Boolean
})

const emit = defineEmits(['update:modelValue', 'created'])

const loading = ref(false)

const form = reactive({
  title: '',
  category: '',
  price: null,
  description: '',
  experience: 0,
  guarantee: 0,
  completion_time: '',
  telegram: '',
  max: ''
})

function closeModal() {
  emit('update:modelValue', false)
  resetForm()
}

function resetForm() {
  form.title = ''
  form.category = ''
  form.price = null
  form.description = ''
  form.experience = 0
  form.guarantee = 0
  form.completion_time = ''
  form.telegram = ''
  form.max = ''
}

async function handleSubmit() {
  loading.value = true
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.post('/api/create-service', form, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    
    if (response.data.success) {
      alert('✅ Услуга успешно создана!')
      closeModal()
      emit('created')
    } else {
      alert('❌ ' + response.data.message)
    }
  } catch (error) {
    alert('❌ Ошибка создания услуги')
    console.error(error)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.modal { 
  display: none; 
  position: fixed; 
  top: 0; 
  left: 0; 
  width: 100%; 
  height: 100%; 
  background: rgba(0, 0, 0, 0.6); 
  backdrop-filter: blur(4px); 
  z-index: 1000; 
  align-items: center; 
  justify-content: center; 
}

.modal.active { 
  display: flex; 
}

.modal-content { 
  background: white; 
  border-radius: 12px; 
  width: 90%; 
  max-width: 500px; 
  max-height: 90vh; 
  overflow-y: auto; 
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); 
  animation: slideIn 0.3s ease; 
}

.modal-header { 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  padding: 20px 24px; 
  border-bottom: 1px solid #e2e8f0; 
}

.modal-header h2 { 
  margin: 0; 
  font-size: 1.25rem; 
  color: #1e293b; 
}

.modal-close { 
  background: none; 
  border: none; 
  font-size: 28px; 
  cursor: pointer; 
  color: #64748b; 
  line-height: 1; 
  padding: 0; 
  width: 32px; 
  height: 32px; 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  border-radius: 6px; 
  transition: all 0.2s; 
}

.modal-close:hover { 
  background: #f1f5f9; 
  color: #1e293b; 
}

.modal-body { 
  padding: 24px; 
}

.form-group { 
  margin-bottom: 16px; 
}

.form-group label { 
  display: block; 
  margin-bottom: 8px; 
  color: #475569; 
  font-size: 14px; 
}

.form-group input, 
.form-group textarea,
.form-group select { 
  width: 100%; 
  padding: 12px; 
  border: 1px solid #e2e8f0; 
  border-radius: 8px; 
  font-size: 14px; 
  font-family: 'Manrope', sans-serif; 
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus { 
  outline: none; 
  border-color: #135bec; 
  box-shadow: 0 0 0 3px rgba(19, 91, 236, 0.1); 
}

.modal-actions { 
  display: flex; 
  gap: 12px; 
  margin-top: 24px; 
}

.modal-actions .btn { 
  flex: 1; 
  padding: 12px; 
  border-radius: 8px; 
  font-weight: 600; 
  cursor: pointer; 
  transition: all 0.2s; 
  border: none; 
  font-family: 'Manrope', sans-serif; 
  font-size: 14px; 
}

.btn-outline { 
  background: transparent; 
  border: 2px solid #135bec; 
  color: #135bec; 
}

.btn-outline:hover { 
  background: #135bec; 
  color: white; 
}

.btn-success { 
  background: #10b981; 
  color: white; 
}

.btn-success:hover { 
  background: #059669; 
}

.btn-success:disabled { 
  background: #9ca3af; 
  cursor: not-allowed; 
}

@keyframes slideIn { 
  from { 
    transform: translateY(-20px); 
    opacity: 0; 
  } 
  to { 
    transform: translateY(0); 
    opacity: 1; 
  } 
}
</style>