<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Регистрация</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleRegister">
          <div class="form-group">
            <label>Роль:</label>
            <div class="role-selector">
              <div class="role-option" :class="{ selected: role === 'customer' }" @click="role = 'customer'">
                <input type="radio" name="userRole" value="customer" v-model="role">
                <span>👤 Заказчик</span>
              </div>
              <div class="role-option" :class="{ selected: role === 'worker' }" @click="role = 'worker'">
                <input type="radio" name="userRole" value="worker" v-model="role">
                <span>🔨 Исполнитель</span>
              </div>
              <div class="role-option" :class="{ selected: role === 'admin' }" @click="role = 'admin'">
                <input type="radio" name="userRole" value="admin" v-model="role">
                <span>🔧 Администратор</span>
              </div>
            </div>
          </div>

          <div class="form-group">
            <label>Email</label>
            <input type="email" v-model="email" required placeholder="email@example.com">
          </div>
          
          <div class="form-group">
            <label>Имя</label>
            <input type="text" v-model="name" required placeholder="Ваше имя">
          </div>
          
          <div class="form-group">
            <label>Пароль</label>
            <input type="password" v-model="password" required minlength="6" placeholder="••••••">
          </div>
          
          <div class="form-group">
            <label>Подтвердите пароль</label>
            <input type="password" v-model="confirmPassword" required placeholder="••••••">
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
import { ref } from 'vue'
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

function closeModal() {
  emit('update:modelValue', false)
  email.value = ''
  name.value = ''
  password.value = ''
  confirmPassword.value = ''
  role.value = 'customer'
}

async function handleRegister() {
  if (password.value !== confirmPassword.value) {
    alert('❌ Пароли не совпадают')
    return
  }
  
  if (password.value.length < 6) {
    alert('❌ Пароль должен быть не менее 6 символов')
    return
  }

  loading.value = true
  try {
    const result = await authStore.register({
      email: email.value,
      password: password.value,
      name: name.value,
      role: role.value
    })
    
    if (result.success) {
      alert('✅ Регистрация успешна! Теперь войдите.')
      closeModal()
      emit('show-login')
    } else {
      alert('❌ ' + result.error)
    }
  } catch (error) {
    console.error('Register error:', error)
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
.form-group input { 
  width: 100%; 
  padding: 12px; 
  border: 1px solid #e2e8f0; 
  border-radius: 8px; 
  font-size: 14px; 
}
.form-group input:focus { 
  outline: none; 
  border-color: #135bec; 
  box-shadow: 0 0 0 3px rgba(19, 91, 236, 0.1); 
}
.role-selector { 
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px; 
}
.role-option { 
  padding: 12px;
  border: 2px solid #e2e8f0; 
  border-radius: 8px; 
  cursor: pointer; 
  text-align: center; 
}
.role-option.selected { 
  border-color: #135bec; 
  background: #eff6ff; 
}
.role-option input { 
  margin-right: 8px; 
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
  cursor: not-allowed; 
}
@keyframes slideIn { 
  from { transform: translateY(-20px); opacity: 0; } 
  to { transform: translateY(0); opacity: 1; } 
}
</style>