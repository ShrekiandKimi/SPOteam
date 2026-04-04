<template>
  <div class="worker-dashboard">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="dashboard-container">
      <h1>Здравствуйте, {{ userName }}!</h1>
      
      <section class="dashboard-section">
        <h2>Статистика</h2>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-number">{{ services ? services.length : 0 }}</div>
            <div class="stat-label">Активных услуг</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ orders ? orders.length : 0 }}</div>
            <div class="stat-label">Всего заказов</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ orders ? orders.filter(o => o.status === 'pending').length : 0 }}</div>
            <div class="stat-label">Новых заявок</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ orders ? orders.filter(o => o.status === 'completed').length : 0 }}</div>
            <div class="stat-label">Завершённых</div>
          </div>
        </div>
      </section>
      
      <section class="dashboard-section">
        <h2>Новые заявки</h2>
        <div v-if="loadingOrders" class="loading">Загрузка...</div>
        <div v-else-if="!orders || orders.length === 0" class="empty">Нет новых заявок</div>
        <div v-else class="orders-list">
          <div v-for="order in orders" :key="order.id" class="order-card">
            <div class="order-header">
              <h3>{{ order.service_title }}</h3>
              <span class="order-price">{{ order.price }} ₽</span>
            </div>
            <p class="order-description">{{ order.service_description }}</p>
            <div class="order-info">
              <div class="info-item">
                <span class="info-label">Клиент:</span>
                <span class="info-value">{{ order.customer_name }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Телефон:</span>
                <span class="info-value">{{ order.customer_phone }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Адрес:</span>
                <span class="info-value">{{ order.customer_address }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Дата:</span>
                <span class="info-value">{{ formatDate(order.created_at) }}</span>
              </div>
            </div>
            <div class="order-status">
              <span :class="['status-badge', getStatusClass(order.status)]">
                {{ getStatusText(order.status) }}
              </span>
            </div>
            
            <!-- 🔹 КНОПКИ ДЛЯ РАЗНЫХ СТАТУСОВ -->
            <div v-if="order.status === 'pending'" class="order-actions">
              <button class="btn btn-success" @click="updateOrderStatus(order.id, 'accepted')">
                ✅ Подтвердить
              </button>
              <button class="btn btn-danger" @click="updateOrderStatus(order.id, 'rejected')">
                ❌ Отклонить
              </button>
            </div>
            
            <!-- 🔹 НОВАЯ КНОПКА: ЗАВЕРШИТЬ ЗАКАЗ -->
            <div v-if="order.status === 'accepted'" class="order-actions">
              <button class="btn btn-primary" @click="completeOrder(order.id)">
                🎉 Завершить заказ
              </button>
            </div>
            
            <div v-if="order.status === 'completed'" class="order-actions">
              <span class="completed-text">✓ Заказ завершён</span>
            </div>
            
            <div v-if="order.status === 'rejected'" class="order-actions">
              <span class="rejected-text">✗ Отклонён</span>
            </div>
          </div>
        </div>
      </section>
      
      <section class="dashboard-section">
        <div class="section-header">
          <h2>Мои услуги</h2>
          <button class="btn btn-primary" @click="showCreateService = true">
            + Добавить услугу
          </button>
        </div>
        
        <div v-if="loadingServices" class="loading">Загрузка...</div>
        <div v-else-if="!services || services.length === 0" class="empty">
          <p>У вас пока нет услуг</p>
          <p style="font-size: 14px; color: #64748b; margin-top: 8px;">
            Создайте первую услугу, чтобы клиенты могли вас найти
          </p>
        </div>
        <div v-else class="services-grid">
          <div v-for="service in services" :key="service.id" class="service-card">
            <div class="service-header">
              <h3>{{ service.title }}</h3>
              <span class="service-price">{{ service.price }} ₽/час</span>
            </div>
            <p class="service-description">{{ service.description }}</p>
            <div class="service-meta">
              <span>Категория: {{ getCategoryName(service.category) }}</span>
              <span>Опыт: {{ service.experience }} лет</span>
            </div>
            <div class="service-actions">
              <button class="btn btn-outline" @click="editService(service)">
                Редактировать
              </button>
              <button class="btn btn-danger" @click="deleteService(service.id)">
                Удалить
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
    
    <Footer />
    
    <CreateServiceForm 
      v-if="showCreateService"
      v-model="showCreateService"
      @created="onServiceCreated"
    />
    
    <EditServiceForm 
      v-if="showEditService"
      v-model="showEditService"
      :service="editingService"
      @updated="onServiceUpdated"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import CreateServiceForm from '@/components/Services/CreateServiceForm.vue'
import EditServiceForm from '@/components/Services/EditServiceForm.vue'

const authStore = useAuthStore()
const services = ref([])
const orders = ref([])
const loadingServices = ref(true)
const loadingOrders = ref(true)
const showCreateService = ref(false)
const showEditService = ref(false)
const showLogin = ref(false)
const showRegister = ref(false)
const editingService = ref(null)

const userName = computed(() => {
  if (authStore.user?.name) return authStore.user.name
  if (authStore.user?.email) return authStore.user.email.split('@')[0]
  return 'Пользователь'
})

onMounted(async () => {
 
  await fetchServices()
  await fetchOrders()
})

async function fetchServices() {
  loadingServices.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-worker-services', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      services.value = response.data.services || []
    } else {
      services.value = []
    }
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error)
    services.value = []
  } finally {
    loadingServices.value = false
  }
}

async function fetchOrders() {
 
  loadingOrders.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-worker-orders', {
      headers: { 'Authorization': `Bearer ${token}` }
    })

    if (response.data && response.data.success) {
      orders.value = response.data.orders || []
      
    } else {
      orders.value = []
    }
  } catch (error) {
    console.error('Ошибка загрузки заказов:', error)
    orders.value = []
  } finally {
    loadingOrders.value = false
  }
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

function formatDate(date) {
  if (!date) return ''
  return new Date(date).toLocaleDateString('ru-RU', {
    day: 'numeric',
    month: 'long',
    year: 'numeric'
  })
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
    pending: 'Ожидает подтверждения',
    accepted: 'В работе',
    rejected: 'Отклонён',
    completed: 'Выполнен',
    cancelled: 'Отменён'
  }
  return texts[status] || status
}

// 🔹 СУЩЕСТВУЮЩАЯ ФУНКЦИЯ (поддерживает все статусы)
async function updateOrderStatus(orderId, status) {
  if (status === 'completed') {
    if (!confirm('Заказ будет помечен как завершённый. Клиент сможет оставить отзыв. Продолжить?')) {
      return
    }
  }
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.post('/api/worker-update-order-status', {
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

// 🔹 НОВАЯ ФУНКЦИЯ ДЛЯ ЗАВЕРШЕНИЯ
async function completeOrder(orderId) {
  await updateOrderStatus(orderId, 'completed')
}

function editService(service) {
  editingService.value = { ...service }
  showEditService.value = true
}

function onServiceCreated() {
  showCreateService.value = false
  fetchServices()
}

function onServiceUpdated() {
  showEditService.value = false
  fetchServices()
}

async function deleteService(serviceId) {
  if (!confirm('Вы уверены, что хотите удалить эту услугу?')) return
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.delete(`/api/delete-service/${serviceId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      
      await fetchServices()
    } else {
      
    }
  } catch (error) {
  
    console.error(error)
  }
}
</script>

<style scoped>
.worker-dashboard { min-height: 100vh; background: #f5f5f5; }
.dashboard-container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
.dashboard-container h1 { font-size: 32px; color: #1e293b; margin-bottom: 32px; }
.dashboard-section { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.dashboard-section h2 { font-size: 24px; color: #1e293b; margin-bottom: 20px; }
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
.stat-card { background: #f8fafc; padding: 24px; border-radius: 8px; text-align: center; }
.stat-number { font-size: 36px; font-weight: 700; color: #135bec; margin-bottom: 8px; }
.stat-label { color: #64748b; font-size: 14px; }
.empty, .loading { text-align: center; padding: 40px; color: #64748b; }
.orders-list { display: flex; flex-direction: column; gap: 16px; }
.order-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
.order-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.order-header h3 { font-size: 18px; color: #1e293b; }
.order-price { font-size: 18px; font-weight: 700; color: #135bec; }
.order-description { color: #64748b; font-size: 14px; margin-bottom: 12px; line-height: 1.5; }
.order-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 12px; }
.info-item { display: flex; flex-direction: column; gap: 4px; }
.info-label { font-size: 12px; color: #94a3b8; }
.info-value { font-size: 14px; color: #1e293b; font-weight: 500; }
.order-status { margin-bottom: 12px; }
.status-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.status-pending { background: #fef3c7; color: #92400e; }
.status-accepted { background: #dbeafe; color: #1e40af; }
.status-rejected { background: #fee2e2; color: #991b1b; }
.status-completed { background: #d1fae5; color: #065f46; }
.status-cancelled { background: #e2e8f0; color: #475569; }
.order-actions { display: flex; gap: 12px; margin-top: 12px; padding-top: 12px; border-top: 1px solid #e2e8f0; }
.completed-text { color: #059669; font-weight: 600; }
.rejected-text { color: #dc2626; font-weight: 600; }
.services-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
.service-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
.service-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.service-header h3 { font-size: 18px; color: #1e293b; }
.service-price { font-size: 18px; font-weight: 700; color: #135bec; }
.service-description { color: #64748b; font-size: 14px; margin-bottom: 12px; line-height: 1.5; }
.service-meta { display: flex; justify-content: space-between; font-size: 13px; color: #475569; margin-bottom: 12px; }
.service-actions { display: flex; gap: 8px; }
.btn { padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; font-family: 'Manrope', sans-serif; font-size: 14px; }
.btn-outline { background: transparent; border: 2px solid #135bec; color: #135bec; }
.btn-outline:hover { background: #135bec; color: white; }
.btn-primary { background: #135bec; color: white; }
.btn-primary:hover { background: #0d4bd6; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(19,91,236,0.3); }
.btn-success { background: #10b981; color: white; }
.btn-success:hover { background: #059669; }
.btn-danger { background: #ef4444; color: white; }
.btn-danger:hover { background: #dc2626; }
</style>