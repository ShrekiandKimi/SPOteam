<template>
  <div class="user-profile">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="profile-container">
      <h1>Мой профиль</h1>
      
      <!-- 🔹 ВКЛАДКИ -->
      <div class="tabs">
        <button 
          :class="['tab-btn', { active: activeTab === 'profile' }]" 
          @click="activeTab = 'profile'"
        >
          👤 Профиль
        </button>
        <button 
          :class="['tab-btn', { active: activeTab === 'orders' }]" 
          @click="activeTab = 'orders'"
        >
          📦 Мои заказы
        </button>
        <button 
          :class="['tab-btn', { active: activeTab === 'security' }]" 
          @click="activeTab = 'security'"
        >
          🔒 Безопасность
        </button>
      </div>
      
      <!-- 🔹 ВКЛАДКА: ПРОФИЛЬ -->
      <div v-if="activeTab === 'profile'" class="tab-content">
        <div v-if="loading" class="loading">Загрузка...</div>
        
        <form v-else @submit.prevent="updateProfile" class="profile-form">
          <div class="form-group">
            <label>Имя *</label>
            <input 
              v-model="form.name" 
              type="text" 
              required
              placeholder="Иван Иванов"
            >
          </div>
          
          <div class="form-group">
            <label>Email</label>
            <input 
              :value="user.email" 
              type="email" 
              disabled
              class="disabled-input"
            >
            <span class="form-hint">Email нельзя изменить</span>
          </div>
          
          <div class="form-group">
            <label>Телефон</label>
            <input 
              v-model="form.phone" 
              type="tel" 
              placeholder="+7 (999) 000-00-00"
            >
          </div>
          
          <div class="form-group">
            <label>Адрес</label>
            <textarea 
              v-model="form.address" 
              rows="3"
              placeholder="Город, улица, дом, квартира"
            ></textarea>
          </div>
          
          <div class="form-group">
            <label>Роль</label>
            <input 
              :value="getRoleName(user.role)" 
              type="text" 
              disabled
              class="disabled-input"
            >
          </div>
          
          <div class="form-actions">
            <button type="submit" class="btn btn-primary" :disabled="saving">
              {{ saving ? 'Сохранение...' : '💾 Сохранить изменения' }}
            </button>
          </div>
        </form>
      </div>
      
      <!-- 🔹 ВКЛАДКА: ЗАКАЗЫ -->
      <div v-if="activeTab === 'orders'" class="tab-content">
        <div v-if="loadingOrders" class="loading">Загрузка...</div>
        
        <div v-else-if="orders.length === 0" class="empty">
          <p>У вас пока нет заказов</p>
        </div>
        
        <div v-else class="orders-list">
          <div v-for="order in orders" :key="order.id" class="order-card">
            <div class="order-header">
              <h3>{{ order.service_title }}</h3>
              <span :class="['status-badge', getStatusClass(order.status)]">
                {{ getStatusText(order.status) }}
              </span>
            </div>
            <div class="order-info">
              <span>Цена: <strong>{{ order.price }} ₽</strong></span>
              <span>Дата: <strong>{{ formatDate(order.created_at) }}</strong></span>
            </div>
            <router-link 
              :to="user.role === 'customer' ? '/customer' : '/worker'" 
              class="btn btn-outline"
            >
              Перейти к заказам
            </router-link>
          </div>
        </div>
      </div>
      
      <!-- 🔹 ВКЛАДКА: БЕЗОПАСНОСТЬ -->
      <div v-if="activeTab === 'security'" class="tab-content">
        <form @submit.prevent="changePassword" class="security-form">
          <div class="form-group">
            <label>Текущий пароль *</label>
            <input 
              v-model="passwordForm.current" 
              type="password" 
              required
              placeholder="••••••••"
            >
          </div>
          
          <div class="form-group">
            <label>Новый пароль *</label>
            <input 
              v-model="passwordForm.new" 
              type="password" 
              required
              placeholder="••••••••"
              minlength="6"
            >
          </div>
          
          <div class="form-group">
            <label>Подтвердите пароль *</label>
            <input 
              v-model="passwordForm.confirm" 
              type="password" 
              required
              placeholder="••••••••"
            >
          </div>
          
          <div class="form-actions">
            <button type="submit" class="btn btn-primary" :disabled="savingPassword">
              {{ savingPassword ? 'Сохранение...' : '🔑 Изменить пароль' }}
            </button>
          </div>
        </form>
        
        <div class="danger-zone">
          <h3>⚠️ Опасная зона</h3>
          <p>Удаление аккаунта необратимо. Все ваши данные будут удалены.</p>
          <button class="btn btn-danger" @click="deleteAccount">
            🗑️ Удалить аккаунт
          </button>
        </div>
      </div>
    </div>
    
    <Footer />
    
    <LoginModal 
      v-if="showLogin"
      v-model="showLogin"
    />
    
    <RegisterModal 
      v-if="showRegister"
      v-model="showRegister"
      @show-login="showLogin = true; showRegister = false"
    />
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import LoginModal from '@/components/Auth/LoginModal.vue'
import RegisterModal from '@/components/Auth/RegisterModal.vue'

const router = useRouter()
const authStore = useAuthStore()

const activeTab = ref('profile')
const loading = ref(true)
const loadingOrders = ref(true)
const saving = ref(false)
const savingPassword = ref(false)
const showLogin = ref(false)
const showRegister = ref(false)

const user = ref({
  id: 0,
  name: '',
  email: '',
  phone: '',
  address: '',
  role: ''
})

const form = reactive({
  name: '',
  phone: '',
  address: ''
})

const passwordForm = reactive({
  current: '',
  new: '',
  confirm: ''
})

const orders = ref([])

onMounted(async () => {
  if (!authStore.isAuthenticated) {
    router.push('/')
    return
  }
  await fetchProfile()
  await fetchOrders()
})

async function fetchProfile() {
  loading.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-profile', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    
    if (response.data && response.data.success) {
      user.value = response.data.user
      form.name = user.value.name
      form.phone = user.value.phone || ''
      form.address = user.value.address || ''
    }
  } catch (error) {
    console.error('Ошибка загрузки профиля:', error)
    if (error.response?.status === 401) {
      authStore.logout()
      router.push('/')
    }
  } finally {
    loading.value = false
  }
}

async function fetchOrders() {
  loadingOrders.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const endpoint = user.value.role === 'customer' 
      ? '/api/get-customer-orders' 
      : '/api/get-worker-orders'
    
    const response = await api.get(endpoint, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    
    if (response.data && response.data.success) {
      orders.value = response.data.orders || []
    }
  } catch (error) {
    console.error('Ошибка загрузки заказов:', error)
  } finally {
    loadingOrders.value = false
  }
}

async function updateProfile() {
  saving.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.put('/api/update-profile', {
      name: form.name,
      phone: form.phone,
      address: form.address
    }, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    
    if (response.data && response.data.success) {
      alert('✅ Профиль обновлён!')
      await fetchProfile()
      // Обновить данные в authStore
      authStore.user.name = form.name
    } else {
      alert('Ошибка: ' + (response.data?.error || 'Неизвестная ошибка'))
    }
  } catch (error) {
    console.error('Ошибка обновления профиля:', error)
    alert('Ошибка подключения к серверу')
  } finally {
    saving.value = false
  }
}

async function changePassword() {
  if (passwordForm.new !== passwordForm.confirm) {
    alert('❌ Пароли не совпадают')
    return
  }
  
  if (passwordForm.new.length < 6) {
    alert('❌ Пароль должен быть не менее 6 символов')
    return
  }
  
  savingPassword.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.post('/api/change-password', {
      current_password: passwordForm.current,
      new_password: passwordForm.new
    }, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    
    if (response.data && response.data.success) {
      alert('✅ Пароль изменён!')
      passwordForm.current = ''
      passwordForm.new = ''
      passwordForm.confirm = ''
    } else {
      alert('Ошибка: ' + (response.data?.error || 'Неверный текущий пароль'))
    }
  } catch (error) {
    console.error('Ошибка смены пароля:', error)
    alert('Ошибка: ' + (error.response?.data?.error || 'Неверный текущий пароль'))
  } finally {
    savingPassword.value = false
  }
}

async function deleteAccount() {
  if (!confirm('⚠️ Вы уверены? Это действие необратимо!')) {
    return
  }
  
  if (!confirm('⚠️ ВСЕ данные будут удалены. Продолжить?')) {
    return
  }
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.delete('/api/delete-account', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    
    if (response.data && response.data.success) {
      alert('Аккаунт удалён')
      authStore.logout()
      router.push('/')
    } else {
      alert('Ошибка удаления аккаунта')
    }
  } catch (error) {
    console.error('Ошибка удаления аккаунта:', error)
    alert('Ошибка подключения к серверу')
  }
}

function getRoleName(role) {
  const names = {
    customer: 'Заказчик',
    worker: 'Исполнитель',
    admin: 'Администратор'
  }
  return names[role] || role
}

function getStatusClass(status) {
  const classes = {
    pending: 'status-pending',
    accepted: 'status-accepted',
    rejected: 'status-rejected',
    completed: 'status-completed',
    cancelled: 'status-cancelled'
  }
  return classes[status] || ''
}

function getStatusText(status) {
  const texts = {
    pending: 'Ожидает',
    accepted: 'В работе',
    rejected: 'Отклонён',
    completed: 'Выполнен',
    cancelled: 'Отменён'
  }
  return texts[status] || status
}

function formatDate(date) {
  if (!date) return ''
  return new Date(date).toLocaleDateString('ru-RU', {
    day: 'numeric',
    month: 'long',
    year: 'numeric'
  })
}
</script>

<style scoped>
.user-profile { min-height: 100vh; background: #f5f5f5; }
.profile-container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
.profile-container h1 { font-size: 32px; color: #1e293b; margin-bottom: 32px; }

/* 🔹 ВКЛАДКИ */
.tabs { display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 2px solid #e2e8f0; padding-bottom: 0; }
.tab-btn { padding: 12px 24px; background: transparent; border: none; border-bottom: 3px solid transparent; cursor: pointer; font-weight: 600; color: #64748b; font-size: 15px; transition: all 0.2s; margin-bottom: -2px; }
.tab-btn:hover { color: #1e293b; background: #f8fafc; }
.tab-btn.active { color: #135bec; border-bottom-color: #135bec; }

/* 🔹 КОНТЕНТ ВКЛАДОК */
.tab-content { background: white; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.profile-form, .security-form { max-width: 600px; }
.form-group { margin-bottom: 24px; }
.form-group label { display: block; margin-bottom: 8px; color: #475569; font-weight: 600; font-size: 14px; }
.form-group input, .form-group textarea { width: 100%; padding: 12px 16px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 15px; font-family: 'Manrope', sans-serif; transition: all 0.2s; }
.form-group input:focus, .form-group textarea:focus { outline: none; border-color: #135bec; box-shadow: 0 0 0 3px rgba(19,91,236,0.1); }
.form-group textarea { resize: vertical; min-height: 80px; }
.disabled-input { background: #f1f5f9; color: #94a3b8; cursor: not-allowed; }
.form-hint { display: block; margin-top: 6px; font-size: 12px; color: #94a3b8; }
.form-actions { margin-top: 32px; }
.btn { padding: 12px 24px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; font-size: 15px; font-family: 'Manrope', sans-serif; }
.btn-primary { background: #135bec; color: white; }
.btn-primary:hover { background: #0d4bd6; transform: translateY(-2px); }
.btn-primary:disabled { background: #94a3b8; cursor: not-allowed; transform: none; }
.btn-outline { background: transparent; border: 2px solid #135bec; color: #135bec; display: inline-block; text-decoration: none; text-align: center; }
.btn-outline:hover { background: #135bec; color: white; }
.btn-danger { background: #ef4444; color: white; }
.btn-danger:hover { background: #dc2626; }

/* 🔹 ЗАКАЗЫ */
.orders-list { display: flex; flex-direction: column; gap: 16px; }
.order-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
.order-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.order-header h3 { font-size: 18px; color: #1e293b; margin: 0; }
.order-info { display: flex; gap: 24px; margin-bottom: 12px; font-size: 14px; color: #64748b; }
.status-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.status-pending { background: #fef3c7; color: #92400e; }
.status-accepted { background: #dbeafe; color: #1e40af; }
.status-rejected { background: #fee2e2; color: #991b1b; }
.status-completed { background: #d1fae5; color: #065f46; }
.status-cancelled { background: #e2e8f0; color: #475569; }

/* 🔹 БЕЗОПАСНОСТЬ */
.danger-zone { margin-top: 40px; padding-top: 32px; border-top: 2px solid #fee2e2; }
.danger-zone h3 { color: #dc2626; margin-bottom: 8px; }
.danger-zone p { color: #64748b; margin-bottom: 16px; font-size: 14px; }

.loading, .empty { text-align: center; padding: 40px; color: #64748b; }

@media (max-width: 768px) {
  .tabs { flex-wrap: wrap; }
  .tab-btn { flex: 1; min-width: 120px; text-align: center; }
  .order-info { flex-direction: column; gap: 8px; }
}
</style>