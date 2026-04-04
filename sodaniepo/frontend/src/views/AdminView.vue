<template>
  <div class="admin-dashboard">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="dashboard-container">
      <h1>🛡️ Панель администратора</h1>
      
      <!-- 🔹 СТАТИСТИКА ПЛАТФОРМЫ -->
      <section class="dashboard-section">
        <h2>📊 Статистика платформы</h2>
        <div v-if="loadingStats" class="loading">Загрузка...</div>
        <div v-else class="stats-grid">
          <div class="stat-card">
            <div class="stat-number">{{ stats.total_users }}</div>
            <div class="stat-label">Всего пользователей</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.total_customers }}</div>
            <div class="stat-label">Заказчиков</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.total_workers }}</div>
            <div class="stat-label">Исполнителей</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.total_services }}</div>
            <div class="stat-label">Услуг</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.total_orders }}</div>
            <div class="stat-label">Заказов</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.total_reviews }}</div>
            <div class="stat-label">Отзывов</div>
          </div>
          <div class="stat-card highlight">
            <div class="stat-number">{{ Math.round(stats.total_revenue) }} ₽</div>
            <div class="stat-label">Общий доход</div>
          </div>
        </div>
      </section>
      
      <!-- 🔹 ВСЕ ПОЛЬЗОВАТЕЛИ -->
      <section class="dashboard-section">
        <h2>👥 Пользователи</h2>
        <div v-if="loadingUsers" class="loading">Загрузка...</div>
        <div v-else-if="users.length === 0" class="empty">Нет пользователей</div>
        <div v-else class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Имя</th>
                <th>Email</th>
                <th>Телефон</th>
                <th>Роль</th>
                <th>Дата регистрации</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="user in users" :key="user.id">
                <td>{{ user.id }}</td>
                <td>{{ user.name }}</td>
                <td>{{ user.email }}</td>
                <td>{{ user.phone || '—' }}</td>
                <td>
                  <span :class="['role-badge', getRoleClass(user.role)]">
                    {{ getRoleName(user.role) }}
                  </span>
                </td>
                <td>{{ formatDate(user.created_at) }}</td>
                <td>
                  <button 
                    v-if="user.id !== currentUserId"
                    class="btn btn-sm btn-danger"
                    @click="deleteUser(user.id)"
                  >
                    🗑️ Удалить
                  </button>
                  <span v-else class="current-user">✓ Вы</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      
      <!-- 🔹 ВСЕ УСЛУГИ (НОВОЕ!) -->
      <section class="dashboard-section">
        <h2>🛠️ Услуги</h2>
        <div v-if="loadingServices" class="loading">Загрузка...</div>
        <div v-else-if="services.length === 0" class="empty">Нет услуг</div>
        <div v-else class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Название</th>
                <th>Исполнитель</th>
                <th>Категория</th>
                <th>Цена</th>
                <th>Рейтинг</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="service in services" :key="service.id">
                <td>{{ service.id }}</td>
                <td>{{ service.title }}</td>
                <td>{{ service.worker_name }}</td>
                <td>{{ getCategoryName(service.category) }}</td>
                <td>{{ service.price }} ₽</td>
                <td>
                  <span v-if="service.rating > 0" class="rating-badge">
                    ⭐ {{ service.rating.toFixed(1) }}
                  </span>
                  <span v-else class="no-rating">—</span>
                </td>
                <td>
                  <button 
                    class="btn btn-sm btn-danger"
                    @click="deleteService(service.id)"
                  >
                    🗑️ Удалить
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      
      <!-- 🔹 ВСЕ ЗАКАЗЫ -->
      <section class="dashboard-section">
        <h2>📦 Все заказы</h2>
        <div v-if="loadingOrders" class="loading">Загрузка...</div>
        <div v-else-if="orders.length === 0" class="empty">Нет заказов</div>
        <div v-else class="table-container">
          <table class="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Услуга</th>
                <th>Клиент</th>
                <th>Цена</th>
                <th>Статус</th>
                <th>Дата</th>
                <th>Действия</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="order in orders" :key="order.id">
                <td>{{ order.id }}</td>
                <td>{{ order.service_title }}</td>
                <td>{{ order.customer_name }}</td>
                <td>{{ order.price }} ₽</td>
                <td>
                  <span :class="['status-badge', getStatusClass(order.status)]">
                    {{ getStatusText(order.status) }}
                  </span>
                </td>
                <td>{{ formatDate(order.created_at) }}</td>
                <td>
                  <select 
                    :value="order.status"
                    @change="updateOrderStatus(order.id, $event.target.value)"
                    class="status-select"
                  >
                    <option value="pending">Ожидает</option>
                    <option value="accepted">Принят</option>
                    <option value="rejected">Отклонён</option>
                    <option value="completed">Выполнен</option>
                    <option value="cancelled">Отменён</option>
                  </select>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
    
    <Footer />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'

const authStore = useAuthStore()

const loadingStats = ref(true)
const loadingUsers = ref(true)
const loadingServices = ref(true)
const loadingOrders = ref(true)
const showLogin = ref(false)
const showRegister = ref(false)

const stats = ref({
  total_users: 0,
  total_customers: 0,
  total_workers: 0,
  total_services: 0,
  total_orders: 0,
  total_reviews: 0,
  total_revenue: 0
})

const users = ref([])
const services = ref([])
const orders = ref([])
const currentUserId = ref(0)

onMounted(async () => {
  currentUserId.value = authStore.user?.id || 0
  await fetchStats()
  await fetchUsers()
  await fetchServices()
  await fetchOrders()
})

async function fetchStats() {
  loadingStats.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-platform-stats', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      stats.value = response.data.stats
    }
  } catch (error) {
    console.error('Ошибка загрузки статистики:', error)
  } finally {
    loadingStats.value = false
  }
}

async function fetchUsers() {
  loadingUsers.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-all-users', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      users.value = response.data.users || []
    }
  } catch (error) {
    console.error('Ошибка загрузки пользователей:', error)
  } finally {
    loadingUsers.value = false
  }
}

async function fetchServices() {
  loadingServices.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-all-services', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      services.value = response.data.services || []
    }
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error)
  } finally {
    loadingServices.value = false
  }
}

async function fetchOrders() {
  loadingOrders.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-orders', {
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

async function deleteUser(userId) {
  if (!confirm(`Вы уверены, что хотите удалить пользователя ${userId}? Все его данные будут удалены!`)) {
    return
  }
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.delete(`/api/delete-user/${userId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      
      await fetchUsers()
      await fetchStats()
    } else {
     
    }
  } catch (error) {
    
    console.error(error)
  }
}

async function deleteService(serviceId) {
  if (!confirm('Вы уверены, что хотите удалить эту услугу?')) {
    return
  }
  
  try {
    const token = localStorage.getItem('accessToken')
    // Используем существующий эндпоинт, но админ может удалять любые услуги
    const response = await api.delete(`/api/delete-service/${serviceId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
    
      await fetchServices()
      await fetchStats()
    } else {
      
    }
  } catch (error) {
    
    console.error(error)
  }
}

async function updateOrderStatus(orderId, status) {
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.post('/api/admin-update-order-status', {
      order_id: orderId,
      status: status
    }, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      
      await fetchOrders()
    } else {
      
    }
  } catch (error) {
   
    console.error(error)
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

function getRoleClass(role) {
  const classes = {
    customer: 'role-customer',
    worker: 'role-worker',
    admin: 'role-admin'
  }
  return classes[role] || ''
}

function getCategoryName(category) {
  const names = {
    construction: 'Строительство',
    repair: 'Ремонт',
    electrical: 'Электрика',
    plumbing: 'Сантехника'
  }
  return names[category] || category
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
    accepted: 'Принят',
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
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}
</script>

<style scoped>
.admin-dashboard { min-height: 100vh; background: #f5f5f5; }
.dashboard-container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; }
.dashboard-container h1 { font-size: 32px; color: #1e293b; margin-bottom: 32px; }
.dashboard-section { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.dashboard-section h2 { font-size: 24px; color: #1e293b; margin-bottom: 20px; }

/* 🔹 СТАТИСТИКА */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
.stat-card { background: #f8fafc; padding: 24px; border-radius: 8px; text-align: center; transition: transform 0.2s; }
.stat-card:hover { transform: translateY(-4px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
.stat-card.highlight { background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; }
.stat-card.highlight .stat-label { color: rgba(255,255,255,0.9); }
.stat-number { font-size: 36px; font-weight: 700; color: #135bec; margin-bottom: 8px; }
.stat-label { color: #64748b; font-size: 14px; font-weight: 600; }

/* 🔹 ТАБЛИЦЫ */
.table-container { overflow-x: auto; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th, .data-table td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #e2e8f0; }
.data-table th { background: #f8fafc; font-weight: 600; color: #475569; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; }
.data-table tr:hover { background: #f8fafc; transition: background 0.2s; }
.data-table td { font-size: 14px; color: #1e293b; }

/* 🔹 БЕЙДЖИ */
.role-badge, .status-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.role-customer { background: #dbeafe; color: #1e40af; }
.role-worker { background: #d1fae5; color: #065f46; }
.role-admin { background: #fef3c7; color: #92400e; }
.status-pending { background: #fef3c7; color: #92400e; }
.status-accepted { background: #dbeafe; color: #1e40af; }
.status-rejected { background: #fee2e2; color: #991b1b; }
.status-completed { background: #d1fae5; color: #065f46; }
.status-cancelled { background: #e2e8f0; color: #475569; }
.rating-badge { background: #fef3c7; color: #92400e; padding: 4px 8px; border-radius: 4px; font-weight: 600; }
.no-rating { color: #94a3b8; }

/* 🔹 КНОПКИ И ЭЛЕМЕНТЫ */
.btn { padding: 8px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; font-size: 13px; }
.btn-sm { padding: 6px 12px; font-size: 12px; }
.btn-danger { background: #ef4444; color: white; }
.btn-danger:hover { background: #dc2626; transform: translateY(-1px); }
.current-user { color: #10b981; font-weight: 600; font-size: 13px; padding: 4px 8px; }
.status-select { padding: 6px 12px; border: 1px solid #e2e8f0; border-radius: 6px; font-size: 13px; cursor: pointer; background: white; }
.status-select:focus { outline: none; border-color: #135bec; box-shadow: 0 0 0 3px rgba(19,91,236,0.1); }

.empty, .loading { text-align: center; padding: 40px; color: #64748b; font-size: 16px; }

@media (max-width: 768px) {
  .stats-grid { grid-template-columns: repeat(2, 1fr); }
  .data-table { font-size: 12px; }
  .data-table th, .data-table td { padding: 8px 12px; }
  .dashboard-container h1 { font-size: 24px; }
}
</style>