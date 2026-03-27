<template>
  <div class="admin-dashboard">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="dashboard-container">
      <h1>🏗️ Панель администратора</h1>
      
      <!-- Все заказы -->
      <section class="dashboard-section">
        <h2>📋 Все заказы</h2>
        <div v-if="loading" class="loading">Загрузка...</div>
        <div v-else-if="orders.length === 0" class="empty">Нет заказов</div>
        <table v-else class="orders-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Клиент</th>
              <th>Услуга</th>
              <th>Цена</th>
              <th>Статус</th>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="order in orders" :key="order.id">
              <td>{{ order.id }}</td>
              <td>{{ order.customer_name }}</td>
              <td>{{ order.service_title }}</td>
              <td>{{ order.price }} ₽</td>
              <td>
                <select v-model="order.status" @change="updateStatus(order)">
                  <option value="pending">Ожидает</option>
                  <option value="confirmed">Подтвержден</option>
                  <option value="in_progress">В работе</option>
                  <option value="completed">Завершен</option>
                  <option value="cancelled">Отменен</option>
                </select>
              </td>
              <td>
                <button class="btn btn-outline" @click="viewOrder(order)">Просмотр</button>
              </td>
            </tr>
          </tbody>
        </table>
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
const orders = ref([])
const loading = ref(true)

onMounted(async () => {
  await fetchOrders()
})

async function fetchOrders() {
  try {
    const response = await api.get('/api/get-orders')
    if (response.data.success) {
      orders.value = response.data.orders
    }
  } catch (error) {
    console.error('Ошибка загрузки заказов:', error)
  } finally {
    loading.value = false
  }
}

async function updateStatus(order) {
  try {
    await api.post('/api/update-order-status', {
      order_id: order.id,
      status: order.status
    })
  } catch (error) {
    console.error('Ошибка обновления статуса:', error)
  }
}

function viewOrder(order) {
  console.log('View order:', order)
}
</script>

<style scoped>
.admin-dashboard {
  min-height: 100vh;
  background: #f5f5f5;
}

.dashboard-container {
  max-width: 1400px;
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

.orders-table {
  width: 100%;
  border-collapse: collapse;
}

.orders-table th,
.orders-table td {
  padding: 12px;
  text-align: left;
  border-bottom: 1px solid #e2e8f0;
}

.orders-table th {
  background: #f8fafc;
  font-weight: 600;
  color: #475569;
}

.orders-table select {
  padding: 6px 12px;
  border: 1px solid #e2e8f0;
  border-radius: 6px;
  font-size: 14px;
}
</style>