import { computed } from 'vue'
import { useAuthStore } from '@/stores/auth'

export function useAuth() {
  const authStore = useAuthStore()

  const isAuthenticated = computed(() => authStore.isAuthenticated)
  const userRole = computed(() => authStore.userRole)
  const userName = computed(() => authStore.userName)

  async function login(email, password) {
    return await authStore.login(email, password)
  }

  async function register(data) {
    return await authStore.register(data)
  }

  function logout() {
    authStore.logout()
  }

  return {
    isAuthenticated,
    userRole,
    userName,
    login,
    register,
    logout
  }
}