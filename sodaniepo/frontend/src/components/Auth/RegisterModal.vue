<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Регистрация</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleSubmit">
          <div class="form-group">
            <label>Имя *</label>
            <input type="text" v-model="form.name" required placeholder="Иван Иванов">
          </div>
          
          <div class="form-group">
            <label>Email *</label>
            <input type="email" v-model="form.email" required placeholder="ivan@example.com">
          </div>
          
          <div class="form-group">
            <label>Телефон *</label>
            <input type="tel" v-model="form.phone" placeholder="Только цифры" @input="phoneError = ''">
            <span v-if="phoneError" style="color: red; font-size: 12px; display: block; margin-top: 4px;">{{ phoneError }}</span>
          </div>
          
          <div class="form-group">
            <label>Пароль *</label>
            <input type="password" v-model="form.password" required placeholder="••••••••">
          </div>
          
          <div class="form-group">
            <label>Подтвердите пароль *</label>
            <input 
              type="password" 
              v-model="form.passwordConfirm" 
              required 
              placeholder="••••••••" 
              @input="passwordError = ''"
            >
            <span v-if="passwordError" style="color: red; font-size: 12px; display: block; margin-top: 4px;">
              {{ passwordError }}
            </span>
          </div>
          
          <div class="form-group">  
            <label>Я:</label>
            <select v-model="form.role" required>
              <option value="">Выберите роль</option>
              <option value="customer">Заказчик</option>
              <option value="worker">Исполнитель</option>
            </select>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading">
            {{ loading ? 'Регистрация...' : 'Зарегистрироваться' }}
          </button>
          
          <p class="login-link">
            Уже есть аккаунт? 
            <a href="#" @click.prevent="showLogin">Войти</a>
          </p>
        </form>
      </div>
    </div>
  </div>
</template>


<script setup>
import { reactive, ref, watch } from 'vue'
import api from '@/api'

const props = defineProps({
  modelValue: Boolean
})
watch(() => props.modelValue, (isOpen) => {
  document.body.style.overflow = isOpen ? 'hidden' : ''
})

const emit = defineEmits(['update:modelValue', 'show-login'])

const loading = ref(false)

// 🔹 Состояния для инлайн-ошибок
const nameError = ref('')
const phoneError = ref('')
const passwordError = ref('')

const form = reactive({
  name: '',
  email: '',
  phone: '',
  password: '',
  passwordConfirm: '',
  role: ''
})

function closeModal() {
  emit('update:modelValue', false)
  resetForm()
}

function resetForm() {
  form.name = ''
  form.email = ''
  form.phone = ''
  form.password = ''
  form.passwordConfirm = ''
  form.role = ''
  nameError.value = ''
  phoneError.value = ''
  passwordError.value = ''
}

function showLogin() {
  emit('show-login')
}

async function handleSubmit() {
  // Сбрасываем ошибки перед новой проверкой
  nameError.value = ''
  phoneError.value = ''
  passwordError.value = ''

  // 🔹 1. Проверка имени
  if (!form.name.trim()) {
    nameError.value = 'Введите ваше имя'
    return
  }

  // 🔹 2. Проверка телефона
  const phoneValue = form.phone.trim()
  if (!phoneValue) {
    phoneError.value = 'Введите номер телефона'
    return
  }
  if (!/^\d+$/.test(phoneValue)) {
    phoneError.value = 'Разрешены только цифры'
    return
  }

  // 🔹 3. Проверка паролей (без alert)
  if (form.password !== form.passwordConfirm) {
    passwordError.value = 'Пароли не совпадают'
    return
  }

  if (form.password.length < 6) {
    passwordError.value = 'Пароль должен быть не менее 6 символов'
    return
  }

  // 🔹 Отправка на сервер
  loading.value = true
  try {
    const response = await api.post('/api/register', {
      name: form.name,
      email: form.email,
      phone: form.phone,
      password: form.password,
      role: form.role
    })

    if (response.data && response.data.success) {
      emit('show-login')
      closeModal()
    } else {
      // Ошибку от сервера можно вывести в console или привязать к конкретному полю
      console.error('Server error:', response.data)
    }
  } catch (error) {
    console.error('Registration error:', error)
  } finally {
    loading.value = false
  }
}

</script>

<style scoped>
/* Ваши стили остаются без изменений */
.modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.6); backdrop-filter: blur(4px); z-index: 1000; align-items: center; justify-content: center; }
.modal.active { display: flex; }
.modal-content { background: white; border-radius: 12px; width: 90%; max-width: 450px; }
.modal-header { display: flex; justify-content: space-between; align-items: center; padding: 20px 24px; border-bottom: 1px solid #e2e8f0; }
.modal-header h2 { margin: 0; font-size: 1.25rem; color: #1e293b; }
.modal-close { background: none; border: none; font-size: 28px; cursor: pointer; color: #64748b; }
.modal-body { padding: 24px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; margin-bottom: 8px; color: #475569; font-size: 14px; }
.form-group input, .form-group select { width: 100%; padding: 12px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; font-family: 'Manrope', sans-serif; }
.form-group input:focus, .form-group select:focus { outline: none; border-color: #135bec; box-shadow: 0 0 0 3px rgba(19,91,236,0.1); }
.btn-primary { background: #135bec; color: white; padding: 12px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; width: 100%; }
.btn-primary:disabled { background: #9ca3af; cursor: not-allowed; }
.login-link { text-align: center; margin-top: 16px; color: #64748b; font-size: 14px; }
.login-link a { color: #135bec; text-decoration: none; }
.login-link a:hover { text-decoration: underline; }
</style>