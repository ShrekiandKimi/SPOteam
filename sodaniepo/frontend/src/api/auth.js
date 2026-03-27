import api from './index'

export const authApi = {
  login: (credentials) => api.post('/api/login', credentials),
  register: (data) => api.post('/api/register', data),
  validateToken: () => api.post('/api/validate-token')
}