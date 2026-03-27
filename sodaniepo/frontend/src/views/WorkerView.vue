<template>
  <div class="worker-dashboard">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="dashboard-container">
      <h1>Здравствуйте, {{ authStore.userName }}! 👋</h1>
      
      <!-- Статистика -->
      <section class="dashboard-section">
        <h2>📊 Статистика</h2>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-number">{{ services.length }}</div>
            <div class="stat-label">Активных услуг</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.rating }}</div>
            <div class="stat-label">Средний рейтинг</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ stats.reviews }}</div>
            <div class="stat-label">Отзывов</div>
          </div>
        </div>
      </section>
      
      <!-- Новые заявки -->
      <section class="dashboard-section">
        <h2>📬 Новые заявки</h2>
        <div v-if="newOrders.length === 0" class="empty">Нет новых заявок</div>
        <div v-else class="orders-list">
          <div v-for="order in newOrders" :key="order.id" class="order-card">
            <h3>{{ order.service_title }}</h3>
            <p>{{ order.service_description }}</p>
            <div class="order-meta">
              <span>💰 {{ order.price }} ₽</span>
              <span>📅 {{ formatDate(order.created_at) }}</span>
            </div>
            <div class="order-actions">
              <button class="btn btn-success" @click="confirmOrder(order.id)">Подтвердить</button>
              <button class="btn btn-outline" @click="rejectOrder(order.id)">Отклонить</button>
            </div>
          </div>
        </div>
      </section>
      
      <!-- Мои услуги -->
      <section class="dashboard-section">
        <h2>🔨 Мои услуги</h2>
        <button class="btn btn-primary" @click="showCreateService = true">+ Добавить услугу</button>
        
        <div v-if="loading" class="loading">Загрузка...</div>
        <div v-else-if="services.length === 0" class="empty">
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
              <span>📁 {{ getCategoryName(service.category) }}</span>
              <span>⭐ {{ service.rating }}</span>
            </div>
            <div class="service-actions">
              <button class="btn btn-outline" @click="deleteService(service.id)">Удалить</button>
            </div>
          </div>
        </div>
      </section>
    </div>
    
    <Footer />
    
    <!-- Форма создания услуги -->
    <CreateServiceForm 
      v-if="showCreateService"
      v-model="showCreateService"
      @created="fetchServices"
    />
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import CreateServiceForm from '@/components/Services/CreateServiceForm.vue'

const authStore = useAuthStore()
const services = ref([])
const newOrders = ref([])
const loading = ref(true)
const showCreateService = ref(false)
const showLogin = ref(false)
const showRegister = ref(false)

const stats = reactive({
  orders: 0,
  rating: 4.8,
  reviews: 12
})

onMounted(async () => {
  await fetchServices()
})

async function fetchServices() {
  loading.value = true
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
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error)
  } finally {
    loading.value = false
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
  return new Date(date).toLocaleDateString('ru-RU')
}

async function deleteService(serviceId) {
  if (!confirm('Вы уверены, что хотите удалить эту услугу?')) return
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.delete(`/api/delete-service/${serviceId}`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    if (response.data.success) {
      alert('✅ Услуга удалена')
      await fetchServices()
    } else {
      alert('❌ ' + response.data.message)
    }
  } catch (error) {
    alert('❌ Ошибка удаления услуги')
    console.error(error)
  }
}

function confirmOrder(orderId) {
  alert('✅ Заказ подтверждён!')
  console.log('Confirm order:', orderId)
}

function rejectOrder(orderId) {
  alert('❌ Заказ отклонён')
  console.log('Reject order:', orderId)
}
</script>

<style scoped>
.worker-dashboard {
  min-height: 100vh;
  background: #f5f5f5;
}

.dashboard-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 40px 20px;
}

.dashboard-container h1 {
  font-size: 32px;
  color: #1e293b;
  margin-bottom: 32px;
}

.dashboard-section {
  background: white;
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.dashboard-section h2 {
  font-size: 24px;
  color: #1e293b;
  margin-bottom: 20px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
}

.stat-card {
  background: #f8fafc;
  padding: 24px;
  border-radius: 8px;
  text-align: center;
}

.stat-number {
  font-size: 36px;
  font-weight: 700;
  color: #135bec;
  margin-bottom: 8px;
}

.stat-label {
  color: #64748b;
  font-size: 14px;
}

.empty {
  text-align: center;
  padding: 40px;
  color: #64748b;
}

.loading {
  text-align: center;
  padding: 40px;
  color: #64748b;
}

.services-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 16px;
  margin-top: 20px;
}

.service-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 16px;
}

.service-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.service-header h3 {
  font-size: 18px;
  color: #1e293b;
}

.service-price {
  font-size: 18px;
  font-weight: 700;
  color: #135bec;
}

.service-description {
  color: #64748b;
  font-size: 14px;
  margin-bottom: 12px;
  line-height: 1.5;
}

.service-meta {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
  color: #475569;
  margin-bottom: 12px;
}

.service-actions {
  display: flex;
  gap: 8px;
}

.orders-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.order-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 16px;
}

.order-meta {
  display: flex;
  gap: 16px;
  color: #475569;
  font-size: 14px;
  margin: 12px 0;
}

.order-actions {
  display: flex;
  gap: 12px;
}

.btn {
  padding: 10px 20px;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  font-family: 'Manrope', sans-serif;
  font-size: 14px;
}

.btn-outline {
  background: transparent;
  border: 2px solid #135bec;
  color: #135bec;
}

.btn-outline:hover {
  background: #135bec;
  color: white;
}

.btn-primary {
  background: #135bec;
  color: white;
}

.btn-primary:hover {
  background: #0d4bd6;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(19, 91, 236, 0.3);
}

.btn-success {
  background: #10b981;
  color: white;
}

.btn-success:hover {
  background: #059669;
}
</style>