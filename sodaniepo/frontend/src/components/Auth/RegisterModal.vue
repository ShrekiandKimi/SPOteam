<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Регистрация</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleRegister">
          <!-- Выбор роли -->
          <div class="form-group">
            <label>Я хочу зарегистрироваться как:</label>
            <div class="role-selector">
              <div 
                class="role-option" 
                :class="{ selected: role === 'customer' }"
                @click="role = 'customer'"
              >
                <input type="radio" name="userRole" value="customer" v-model="role">
                <span class="role-title">👤 Заказчик</span>
                <span class="role-desc">Искать услуги</span>
              </div>
              <div 
                class="role-option" 
                :class="{ selected: role === 'worker' }"
                @click="role = 'worker'"
              >
                <input type="radio" name="userRole" value="worker" v-model="role">
                <span class="role-title">🔨 Исполнитель</span>
                <span class="role-desc">Предлагать услуги</span>
              </div>
            </div>
          </div>

          <!-- Общие поля -->
          <div class="form-group">
            <label>Email</label>
            <input 
              type="email" 
              v-model="email" 
              required 
              placeholder="your@email.com"
            >
            <div class="form-error" :class="{ active: errors.email }">Неверный формат email</div>
          </div>
          
          <div class="form-group">
            <label>Имя</label>
            <input 
              type="text" 
              v-model="name" 
              required 
              placeholder="Ваше имя"
            >
          </div>
          
          <div class="form-group">
            <label>Пароль</label>
            <input 
              type="password" 
              v-model="password" 
              required 
              placeholder="••••••••" 
              minlength="6"
            >
            <div class="form-error" :class="{ active: errors.password }">Минимум 6 символов</div>
          </div>
          
          <div class="form-group">
            <label>Подтвердите пароль</label>
            <input 
              type="password" 
              v-model="confirmPassword" 
              required 
              placeholder="••••••••"
            >
            <div class="form-error" :class="{ active: errors.confirm }">Пароли не совпадают</div>
          </div>

          <!-- Поля для исполнителя -->
          <div v-if="role === 'worker'" class="worker-fields active">
            <h3 style="margin-bottom: 16px; color: #1e293b;">📝 Информация о вас</h3>
            <div class="form-group">
              <label>Специальность</label>
              <input type="text" v-model="workerProfile.specialty" placeholder="Например: Сантехник, Электрик">
            </div>
            <div class="form-group">
              <label>Опыт работы (лет)</label>
              <input type="number" v-model.number="workerProfile.experience_years" min="0" placeholder="5">
            </div>
            <div class="form-group">
              <label>Телефон</label>
              <input type="tel" v-model="workerProfile.phone" placeholder="+7 (999) 123-45-67">
            </div>
            <div class="form-group">
              <label>Telegram</label>
              <input type="text" v-model="workerProfile.telegram" placeholder="@username">
            </div>
            <div class="form-group">
              <label>О себе</label>
              <textarea v-model="workerProfile.description" rows="3" placeholder="Расскажите о своём опыте и навыках..."></textarea>
            </div>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading">
            {{ loading ? '⏳ Регистрация...' : 'Зарегистрироваться' }}
          </button>
        </form>
        
        <p style="text-align: center; margin-top: 16px; color: #64748b;">
          Уже есть аккаунт? 
          <a href="#" @click.prevent="switchToLogin" style="color: #135bec;">Войти</a>
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive } from 'vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  modelValue: Boolean
})

const emit = defineEmits(['update:modelValue', 'show-login'])

const authStore = useAuthStore()
const role = ref('customer')
const email = ref('')
const name = ref('')
const password = ref('')
const confirmPassword = ref('')
const loading = ref(false)

const workerProfile = reactive({
  specialty: '',
  experience_years: 0,
  phone: '',
  telegram: '',
  description: ''
})

const errors = reactive({
  email: false,
  password: false,
  confirm: false
})

function closeModal() {
  emit('update:modelValue', false)
  resetForm()
}

function resetForm() {
  email.value = ''
  name.value = ''
  password.value = ''
  confirmPassword.value = ''
  role.value = 'customer'
  Object.keys(errors).forEach(key => errors[key] = false)
}

async function handleRegister() {
  // Валидация
  errors.email = !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)
  errors.password = password.value.length < 6
  errors.confirm = password.value !== confirmPassword.value
  
  if (Object.values(errors).some(e => e)) return

  loading.value = true
  try {
    const registerData = {
      email: email.value,
      password: password.value,
      name: name.value,
      role: role.value
    }
    
    if (role.value === 'worker') {
      registerData.worker_profile = { ...workerProfile }
    }
    
    const result = await authStore.register(registerData)
    
    if (result.success) {
      alert('✅ Регистрация успешна! Теперь вы можете войти.')
      closeModal()
      emit('show-login')
    } else {
      alert('❌ ' + result.error)
    }
  } catch (error) {
    alert('❌ Ошибка подключения к серверу')
  } finally {
    loading.value = false
  }
}

function switchToLogin() {
  closeModal()
  emit('show-login')
}
</script>

<style scoped>
/* Стили уже есть в global CSS */
</style>