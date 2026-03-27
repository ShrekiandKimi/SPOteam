<template>
  <div class="customer-dashboard">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="dashboard-container">
      <h1>Здравствуйте, {{ authStore.userName }}! 👋</h1>
      
      <!-- Мои заявки -->
      <section class="dashboard-section">
        <h2>📋 Мои заявки</h2>
        <div v-if="loading" class="loading">Загрузка...</div>
        <div v-else-if="orders.length === 0" class="empty">
          <p>У вас пока нет заявок</p>
          <button class="btn btn-primary" @click="goToSearch">Найти исполнителя</button>
        </div>
        <div v-else class="orders-list">
          <div v-for="order in orders" :key="order.id" class="order-card">
            <div class="order-header">
              <h3>{{ order.service_title }}</h3>
              <span class="order-status" :class="order.status">{{ getStatusLabel(order.status) }}</span>
            </div>
            <p class="order-description">{{ order.service_description }}</p>
            <div class="order-meta">
              <span>💰 {{ order.price }} ₽</span>
              <span>📅 {{ formatDate(order.created_at) }}</span>
            </div>
            <div class="order-actions">
              <button class="btn btn-outline" @click="viewOrder(order)">Перейти к заказу</button>
              <button v-if="order.status === 'pending'" class="btn btn-outline" @click="cancelOrder(order.id)">Отменить</button>
            </div>
          </div>
        </div>
      </section>
      
      <!-- Рекомендации -->
      <section class="dashboard-section">
        <h2>⭐ Рекомендации</h2>
        <p class="empty">Исполнители будут отображаться здесь на основе ваших заказов</p>
      </section>
    </div>
    
    <Footer />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'

const router = useRouter()
const authStore = useAuthStore()
const orders = ref([])
const loading = ref(true)

onMounted(async () => {
  await fetchOrders()
})

async function fetchOrders() {
  try {
    const response = await api.get('/api/get-customer-orders')
    if (response.data.success) {
      orders.value = response.data.orders
    }
  } catch (error) {
    console.error('Ошибка загрузки заказов:', error)
  } finally {
    loading.value = false
  }
}

function getStatusLabel(status) {
  const labels = {
    pending: 'Ожидает подтверждения',
    confirmed: 'Подтвержден',
    in_progress: 'В работе',
    completed: 'Завершен',
    cancelled: 'Отменен'
  }
  return labels[status] || status
}

function formatDate(date) {
  return new Date(date).toLocaleDateString('ru-RU')
}

function goToSearch() {
  router.push('/')
}

function viewOrder(order) {
  // Детали заказа
  console.log('View order:', order)
}

async function cancelOrder(orderId) {
  if (confirm('Вы уверены, что хотите отменить заказ?')) {
    // Логика отмены
    console.log('Cancel order:', orderId)
  }
}
</script>

<style scoped>
.customer-dashboard {
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

.loading, .empty {
  text-align: center;
  padding: 40px;
  color: #64748b;
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

.order-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.order-header h3 {
  font-size: 18px;
  color: #1e293b;
}

.order-status {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
}

.order-status.pending { background: #fef3c7; color: #92400e; }
.order-status.confirmed { background: #dbeafe; color: #1e40af; }
.order-status.in_progress { background: #e0e7ff; color: #3730a3; }
.order-status.completed { background: #d1fae5; color: #065f46; }
.order-status.cancelled { background: #fee2e2; color: #991b1b; }

.order-description {
  color: #64748b;
  margin-bottom: 12px;
}

.order-meta {
  display: flex;
  gap: 16px;
  color: #475569;
  font-size: 14px;
  margin-bottom: 16px;
}

.order-actions {
  display: flex;
  gap: 12px;
}
</style>