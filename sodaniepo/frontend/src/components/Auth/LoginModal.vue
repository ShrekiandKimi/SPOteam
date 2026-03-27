<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content">
      <div class="modal-header">
        <h2>Вход в систему</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      <div class="modal-body">
        <form @submit.prevent="handleLogin">
          <div class="form-group">
            <label>Email</label>
            <input 
              type="email" 
              v-model="email" 
              required 
              placeholder="your@email.com"
            >
          </div>
          <div class="form-group">
            <label>Пароль</label>
            <input 
              type="password" 
              v-model="password" 
              required 
              placeholder="••••••••"
            >
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
import { ref } from 'vue'
import { useAuthStore } from '@/stores/auth'

const props = defineProps({
  modelValue: Boolean
})

const emit = defineEmits(['update:modelValue', 'show-register'])

const authStore = useAuthStore()
const email = ref('')
const password = ref('')
const loading = ref(false)

function closeModal() {
  emit('update:modelValue', false)
  email.value = ''
  password.value = ''
}

async function handleLogin() {
  loading.value = true
  try {
    const result = await authStore.login(email.value, password.value)
    if (result.success) {
      closeModal()
    } else {
      alert('❌ ' + result.error)
    }
  } catch (error) {
    alert('❌ Ошибка подключения к серверу')
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
/* Стили из auto.html уже есть в assets/styles.css */
</style>