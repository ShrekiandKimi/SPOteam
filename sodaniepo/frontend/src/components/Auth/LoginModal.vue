<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Вход</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleLogin">
          <div class="form-group">
            <label>Email</label>
            <input type="email" v-model="form.email" required placeholder="your@email.com">
          </div>
          
          <div class="form-group">
            <label>Пароль</label>
            <input type="password" v-model="form.password" required placeholder="••••••••">
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%" :disabled="loading">
            {{ loading ? '⏳ Вход...' : 'Войти' }}
          </button>
        </form>
        
        <p style="text-align: center; margin-top: 16px; color: #64748b;">
          Нет аккаунта? 
          <a href="#" @click.prevent="switchToRegister" style="color: #135bec;">Зарегистрироваться</a>
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'

const props = defineProps({
  modelValue: Boolean
})

const emit = defineEmits(['update:modelValue', 'show-register'])

const authStore = useAuthStore()
const loading = ref(false)

const form = reactive({
  email: '',
  password: ''
})

function closeModal() {
  emit('update:modelValue', false)
  form.email = ''
  form.password = ''
}

async function handleLogin() {
  loading.value = true
  
  try {
    const response = await api.post('/api/login', {
      email: form.email,
      password: form.password
    })
    
    
    
    if (response.data.success) {
      const user = {
        email: form.email,
        role: response.data.role,
        name: form.email.split('@')[0]
      }
      
      localStorage.setItem('accessToken', response.data.accessToken)
      localStorage.setItem('user', JSON.stringify(user))
      localStorage.setItem('role', response.data.role)
      
      authStore.$patch({
        user: user,
        token: response.data.accessToken
      })
      
      
      closeModal()
      
      setTimeout(() => {
        window.location.reload()
      }, 100)
    } else {
     
    }
  } catch (error) {
    console.error('Login error:', error)
    if (error.response) {
  
    } else {
     
    }
  } finally {
    loading.value = false
  }
}

function switchToRegister() {
  closeModal()
  emit('show-register')
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
  max-width: 450px; 
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
  margin-top: 8px; 
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