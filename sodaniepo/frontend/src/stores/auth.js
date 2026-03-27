import { defineStore } from 'pinia'
import api from '@/api'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: JSON.parse(localStorage.getItem('user')) || null,
    token: localStorage.getItem('accessToken') || null
  }),

  getters: {
    isAuthenticated: (state) => !!state.token
  },

  actions: {
    async register(userData) {
      try {
        const response = await api.post('/api/register', userData)
        
        if (response.status === 201 || response.status === 200) {
          return { success: true, data: response.data }
        }
        return { success: false, error: response.data.error || 'Ошибка регистрации' }
      } catch (error) {
        console.error('Register error:', error)
        if (error.response) {
          return { success: false, error: error.response.data.error || 'Ошибка регистрации' }
        }
        return { success: false, error: 'Ошибка подключения к серверу' }
      }
    },

    async login(credentials) {
      try {
        const response = await api.post('/api/login', credentials)
        
        if (response.data.success) {
          const user = {
            email: credentials.email,
            role: response.data.role,
            name: credentials.email.split('@')[0]
          }
          
          this.user = user
          this.token = response.data.accessToken
          
          localStorage.setItem('user', JSON.stringify(user))
          localStorage.setItem('accessToken', response.data.accessToken)
          localStorage.setItem('role', response.data.role)
          
          return { success: true }
        }
        return { success: false, error: response.data.message }
      } catch (error) {
        console.error('Login error:', error)
        return { success: false, error: 'Ошибка подключения к серверу' }
      }
    },

    logout() {
      this.user = null
      this.token = null
      
      localStorage.removeItem('user')
      localStorage.removeItem('accessToken')
      localStorage.removeItem('role')
    }
  }
})