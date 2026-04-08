<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Добавить услугу</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleSubmit">
          <div class="form-group">
            <label>Название услуги *</label>
            <input type="text" v-model="form.title" required placeholder="Например: Ремонт сантехники">
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
          
          <div class="form-row">
            <div class="form-group">
              <label>Цена (₽/час) *</label>
              <input type="number" v-model.number="form.price" required min="100" placeholder="1000" @input="errors.description = ''">
            </div>
            <div class="form-group">
              <label>Опыт (лет)</label>
              <input type="number"required  v-model.number="form.experience" min="0" placeholder="5">
            </div>
          </div>
          
          <div class="form-group">
            <label>Ссылка на резюме:</label>
<<<<<<< HEAD
            <textarea v-model="form.description" required rows="4" placeholder="Прикрепите ссылку на резюме:" @input="errors.description = ''"
            ></textarea>
=======
            <textarea v-model="form.description" required rows="4" placeholder="Прикрепите ссылку на резюме:"></textarea>
>>>>>>> cc80adb (Все что говорил преподователь изменил, осталась маска для услуги)
          </div>
          
          <div class="form-row">
            <div class="form-group">
              <label>Гарантия (мес)</label>
              <input type="number" v-model.number="form.guarantee" min="0" placeholder="12" required >
            </div>
            <div class="form-group">
              <label>Срок выполнения</label>
              <input type="text" v-model="form.completion_time" placeholder="1-3 дня" required>
            </div>
          </div>
          
          <div class="form-group">
            <label>Telegram</label>
            <input type="text" v-model="form.telegram" placeholder="@username" required >
          </div>
          
          <div class="form-group">
            <label>MAX</label>
            <input type="text" v-model="form.max" placeholder="88005553535" required>
          </div>
          <div class="form-group">
            <label>📝 О себе / Опыт работы по этой услуге</label>
            <textarea 
              v-model="form.bio" 
              rows="3" 
              placeholder="Например: 5 лет опыта в плиточных работах, есть свой инструмент..."
            ></textarea>
          </div>
          <div class="form-group">
            <label>📝 О себе / Опыт работы по этой услуге</label>
            <textarea 
              v-model="form.bio" 
              rows="3" 
              placeholder="Например: 5 лет опыта в плиточных работах, есть свой инструмент..."
            ></textarea>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading">
            {{ loading ? 'Сохранение...' : 'Добавить услугу' }}
          </button>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import api from '@/api'

const props = defineProps({ modelValue: Boolean })
const emit = defineEmits(['update:modelValue', 'created'])

const loading = ref(false)

// 🔹 Ошибки валидации
const errors = reactive({
  title: '',
  category: '',
  price: '',
  description: '',
  max: ''
})

const form = reactive({
  title: '',
  category: '',
  price: null,
  experience: 0,
  description: '',
  guarantee: 0,
  completion_time: '',
  telegram: '',
  max: '',
  bio: ''
})

function closeModal() {
  emit('update:modelValue', false)
  resetForm()
}

function resetForm() {
<<<<<<< HEAD
  Object.assign(form, { 
    title: '', category: '', price: null, experience: 0, description: '', 
    guarantee: 0, completion_time: '', telegram: '', max: '' 
  })
  Object.keys(errors).forEach(k => errors[k] = '')
=======
  form.title = ''
  form.category = ''
  form.price = null
  form.experience = 0
  form.description = ''
  form.guarantee = 0
  form.completion_time = ''
  form.telegram = ''
  form.max = ''
  form.bio = ''
>>>>>>> cc80adb (Все что говорил преподователь изменил, осталась маска для услуги)
}

async function handleSubmit() {
  // Сброс ошибок
  Object.keys(errors).forEach(k => errors[k] = '')
  let isValid = true

  if (!form.title.trim()) { errors.title = 'Введите название услуги'; isValid = false }
  if (!form.category) { errors.category = 'Выберите категорию'; isValid = false }
  if (!form.price || form.price <= 0) { errors.price = 'Укажите корректную цену'; isValid = false }
  if (!form.description.trim()) { errors.description = 'Добавьте описание услуги'; isValid = false }
  if (!form.max.trim()) { errors.max = 'Укажите номер телефона для связи'; isValid = false }

  if (!isValid) return // Блокируем отправку при ошибках

  loading.value = true
  try {
    const response = await api.post('/api/create-service', form)
    if (response.data.success) {
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
.modal-content { background: white; border-radius: 12px; width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; box-shadow: 0 20px 60px rgba(0,0,0,0.3); animation: slideIn 0.3s ease; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 20px 24px; border-bottom: 1px solid #e2e8f0; }
.modal-header h2 { margin: 0; font-size: 1.25rem; color: #1e293b; }
.modal-close { background: none; border: none; font-size: 28px; cursor: pointer; color: #64748b; }
.modal-body { padding: 24px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 8px; color: #475569; font-size: 14px; }
.form-group input, .form-group textarea, .form-group select { width: 100%; padding: 12px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; font-family: 'Manrope', sans-serif; }
.form-group input:focus, .form-group textarea:focus, .form-group select:focus { outline: none; border-color: #135bec; box-shadow: 0 0 0 3px rgba(19,91,236,0.1); }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.btn-primary { background: #135bec; color: white; padding: 12px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; }
.btn-primary:disabled { background: #9ca3af; cursor: not-allowed; }
@keyframes slideIn { from { transform: translateY(-20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
</style>