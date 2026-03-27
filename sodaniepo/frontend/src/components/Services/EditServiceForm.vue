<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Редактировать услугу</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleSubmit">
          <div class="form-group">
            <label>Название услуги *</label>
            <input type="text" v-model="form.title" required>
          </div>
          
          <div class="form-group">
            <label>Категория *</label>
            <select v-model="form.category" required>
              <option value="construction">Строительство</option>
              <option value="repair">Ремонт</option>
              <option value="electrical">Электрика</option>
              <option value="plumbing">Сантехника</option>
            </select>
          </div>
          
          <div class="form-row">
            <div class="form-group">
              <label>Цена (₽/час) *</label>
              <input type="number" v-model.number="form.price" required min="100">
            </div>
            <div class="form-group">
              <label>Опыт (лет)</label>
              <input type="number" v-model.number="form.experience" min="0">
            </div>
          </div>
          
          <div class="form-group">
            <label>Описание *</label>
            <textarea v-model="form.description" required rows="4"></textarea>
          </div>
          
          <div class="form-row">
            <div class="form-group">
              <label>Гарантия (мес)</label>
              <input type="number" v-model.number="form.guarantee" min="0">
            </div>
            <div class="form-group">
              <label>Срок выполнения</label>
              <input type="text" v-model="form.completion_time">
            </div>
          </div>
          
          <div class="form-group">
            <label>Telegram</label>
            <input type="text" v-model="form.telegram">
          </div>
          
          <div class="form-group">
            <label>MAX</label>
            <input type="text" v-model="form.max">
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading">
            {{ loading ? 'Сохранение...' : 'Сохранить изменения' }}
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

const emit = defineEmits(['update:modelValue', 'updated'])

const loading = ref(false)

const form = reactive({
  title: '',
  category: '',
  price: null,
  experience: 0,
  description: '',
  guarantee: 0,
  completion_time: '',
  telegram: '',
  max: ''
})

watch(() => props.service, (newService) => {
  if (newService) {
    form.title = newService.title
    form.category = newService.category
    form.price = newService.price
    form.experience = newService.experience
    form.description = newService.description
    form.guarantee = newService.guarantee
    form.completion_time = newService.completion_time
    form.telegram = newService.telegram
    form.max = newService.max
  }
}, { immediate: true })

function closeModal() {
  emit('update:modelValue', false)
}

async function handleSubmit() {
  loading.value = true
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.put(`/api/update-service/${props.service.id}`, form, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    
    if (response.data.success) {
      alert('Услуга обновлена!')
      emit('updated')
      closeModal()
    } else {
      alert('Ошибка: ' + response.data.message)
    }
  } catch (error) {
    console.error('Ошибка обновления услуги:', error)
    alert('Ошибка подключения к серверу')
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
  max-width: 600px; 
  max-height: 90vh; 
  overflow-y: auto; 
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
}
.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus { 
  outline: none; 
  border-color: #135bec; 
}
.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.btn-primary { 
  background: #135bec; 
  color: white; 
  padding: 12px; 
  border: none; 
  border-radius: 8px; 
  font-weight: 600; 
  cursor: pointer; 
}
.btn-primary:disabled { 
  background: #9ca3af; 
}
</style>