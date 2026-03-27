import { ref } from 'vue'
import api from '@/api'

export function useServices() {
  const services = ref([])
  const loading = ref(false)
  const error = ref(null)

  async function fetchServices() {
    loading.value = true
    error.value = null
    
    try {
      const response = await api.get('/api/get-all-services')
      if (response.data.success) {
        services.value = response.data.services
      }
    } catch (err) {
      error.value = err.message
      console.error('Ошибка загрузки услуг:', err)
    } finally {
      loading.value = false
    }
  }

  async function fetchWorkerServices() {
    loading.value = true
    error.value = null
    
    try {
      const token = localStorage.getItem('accessToken')
      const response = await api.get('/api/get-worker-services', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      if (response.data.success) {
        services.value = response.data.services
      }
    } catch (err) {
      error.value = err.message
      console.error('Ошибка загрузки услуг:', err)
    } finally {
      loading.value = false
    }
  }

  async function createService(serviceData) {
    try {
      const token = localStorage.getItem('accessToken')
      const response = await api.post('/api/create-service', serviceData, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      return response.data
    } catch (err) {
      console.error('Ошибка создания услуги:', err)
      return { success: false, message: err.message }
    }
  }

  async function deleteService(serviceId) {
    try {
      const token = localStorage.getItem('accessToken')
      const response = await api.delete(`/api/delete-service/${serviceId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
      return response.data
    } catch (err) {
      console.error('Ошибка удаления услуги:', err)
      return { success: false, message: err.message }
    }
  }

  return {
    services,
    loading,
    error,
    fetchServices,
    fetchWorkerServices,
    createService,
    deleteService
  }
}