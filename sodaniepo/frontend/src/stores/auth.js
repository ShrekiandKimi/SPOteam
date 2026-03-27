import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { authApi } from '@/api/auth'

export const useAuthStore = defineStore('auth', () => {
  const user = ref(JSON.parse(localStorage.getItem('user') || 'null'))
  const token = ref(localStorage.getItem('accessToken'))
  
  const isAuthenticated = computed(() => !!token.value)
  const userRole = computed(() => user.value?.role)
  const userName = computed(() => user.value?.name)

  async function login(email, password) {
    try {
      const response = await authApi.login({ email, password })
      
      if (response.data.success) {
        token.value = response.data.accessToken
        user.value = {
          email: response.data.email,
          role: response.data.role,
          name: response.data.name || email.split('@')[0]
        }
        
        localStorage.setItem('accessToken', token.value)
        localStorage.setItem('user', JSON.stringify(user.value))
        localStorage.setItem('role', user.value.role)
        
        return { success: true }
      }
      return { success: false, error: response.data.message }
    } catch (error) {
      return { success: false, error: 'Ошибка подключения к серверу' }
    }
  }

  async function register(data) {
    try {
      const response = await authApi.register(data)
      return { success: response.ok, data: await response.json() }
    } catch (error) {
      return { success: false, error: 'Ошибка регистрации' }
    }
  }

  function logout() {
    localStorage.clear()
    token.value = null
    user.value = null
  }

  return {
    user,
    token,
    isAuthenticated,
    userRole,
    userName,
    login,
    register,
    logout
  }
})