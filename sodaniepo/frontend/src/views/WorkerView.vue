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
            <div class="stat-number">{{ stats.orders }}</div>
            <div class="stat-label">Заказов за месяц</div>
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
        <div v-if="services.length > 0" class="services-grid">
          <div v-for="service in services" :key="service.id" class="service-card">
            <h3>{{ service.title }}</h3>
            <p>{{ service.price }} ₽/час</p>
            <button class="btn btn-outline" @click="deleteService(service.id)">Удалить</button>
          </div>
        </div>
      </section>
    </div>
    
    <Footer />
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useServices } from '@/composables/useServices'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'

const authStore = useAuthStore()
const { services, fetchServices } = useServices()
const newOrders = ref([])
const loading = ref(true)

const stats = reactive({
  orders: 0,
  rating: 0,
  reviews: 0
})

onMounted(async () => {
  await fetchServices()
  await fetchStats()
})

async function fetchStats() {
  // Загрузка статистики
  stats.orders = 5
  stats.rating = 4.8
  stats.reviews = 12
  loading.value = false
}

function confirmOrder(orderId) {
  console.log('Confirm order:', orderId)
}

function rejectOrder(orderId) {
  console.log('Reject order:', orderId)
}

async function deleteService(serviceId) {
  if (confirm('Удалить эту услугу?')) {
    // Логика удаления
    console.log('Delete service:', serviceId)
  }
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
</style>