<template>
  <div class="customer-dashboard">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="dashboard-container">
      <h1>Здравствуйте, {{ userName }}!</h1>
      
      <section class="dashboard-section">
        <h2>Статистика</h2>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="stat-number">{{ orders ? orders.length : 0 }}</div>
            <div class="stat-label">Всего заказов</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ activeOrders }}</div>
            <div class="stat-label">Активных</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">{{ completedOrders }}</div>
            <div class="stat-label">Завершённых</div>
          </div>
        </div>
      </section>
      
      <section class="dashboard-section">
        <h2>Мои заказы</h2>
        <div v-if="loading" class="loading">Загрузка...</div>
        <div v-else-if="!orders || orders.length === 0" class="empty">
          <p>У вас пока нет заказов</p>
          <p style="font-size: 14px; color: #64748b; margin-top: 8px;">
            Перейдите на главную чтобы выбрать услугу
          </p>
        </div>
        <div v-else class="orders-list">
          <div v-for="order in orders" :key="order.id" class="order-card">
            <div class="order-header">
              <h3>{{ order.service_title }}</h3>
              <span :class="['status-badge', getStatusClass(order.status)]">
                {{ getStatusText(order.status) }}
              </span>
            </div>
            <p class="order-description">{{ order.service_description }}</p>
            <div class="order-info">
              <div class="info-item">
                <span class="info-label">Цена:</span>
                <span class="info-value">{{ order.price }} ₽</span>
              </div>
              <div class="info-item">
                <span class="info-label">Дата:</span>
                <span class="info-value">{{ formatDate(order.created_at) }}</span>
              </div>
            </div>
            
            <!-- 🔹 БЛОК ИСПОЛНИТЕЛЯ — ИСПРАВЛЕННЫЙ -->
            <div v-if="order.worker_name && order.status !== 'pending' && order.status !== 'cancelled'" class="worker-info">
              <div class="worker-header">
                <div class="worker-details">
                  <h4>Исполнитель:</h4>
                  <p class="worker-name">{{ order.worker_name }}</p>
                  <p v-if="order.worker_phone" class="worker-phone">
                    📞 <a :href="'tel:' + order.worker_phone" class="phone-link">{{ order.worker_phone }}</a>
                  </p>
                </div>
                <button class="btn btn-contact" @click="openContactModal(order)">
                  Связаться
                </button>
              </div>
            </div>
            
            <div class="order-actions">
              <button 
                v-if="order.status === 'pending'" 
                class="btn btn-danger"
                @click="cancelOrder(order.id)"
              >
                Отменить
              </button>
              <button 
                v-if="order.status === 'completed' && !order.has_review" 
                class="btn btn-primary"
                @click="openReviewForm(order)"
              >
                Оставить отзыв
              </button>
            </div>
          </div>
        </div>
      </section>
    </div>
    
    <Footer />
    
    <!-- 🔹 МОДАЛЬНОЕ ОКНО ВЫБОРА МЕССЕНДЖЕРА -->
    <div v-if="showContactModal" class="modal" :class="{ active: showContactModal }" @click.self="closeContactModal">
      <div class="modal-content">
        <div class="modal-header">
          <h2>Связаться с исполнителем</h2>
          <button class="modal-close" @click="closeContactModal">×</button>
        </div>
        <div class="modal-body">
          <p class="modal-text">Выберите удобный способ связи:</p>
          
          <div class="messenger-options">
            <a 
              v-if="selectedOrder?.worker_telegram"
              :href="'https://t.me/' + selectedOrder.worker_telegram.replace('@', '')"
              target="_blank"
              class="messenger-btn telegram"
            >
              <div class="messenger-info">
                <strong>Telegram</strong>
                <span>{{ selectedOrder.worker_telegram }}</span>
              </div>
            </a>
            
            <a 
              v-if="selectedOrder?.worker_phone"
              :href="'tel:' + selectedOrder.worker_phone"
              class="messenger-btn phone"
            >
              <div class="messenger-info">
                <strong>MAX (телефон)</strong>
                <span>{{ selectedOrder.worker_phone }}</span>
              </div>
            </a>
          </div>
          
          <div v-if="!selectedOrder?.worker_telegram && !selectedOrder?.worker_phone" class="no-contacts">
            <p>⚠️ Исполнитель не указал контакты</p>
          </div>
        </div>
      </div>
    </div>
    
    <OrderForm 
      v-if="showOrderForm"
      v-model="showOrderForm"
      :service="selectedService"
      @created="onOrderCreated"
    />
    
    <ReviewForm 
      v-if="showReviewForm"
      v-model="showReviewForm"
      :order="selectedOrder"
      @created="onReviewCreated"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import OrderForm from '@/components/Services/OrderForm.vue'
import ReviewForm from '@/components/Services/ReviewForm.vue'

const authStore = useAuthStore()
const orders = ref([])
const loading = ref(true)
const showOrderForm = ref(false)
const showReviewForm = ref(false)
const showContactModal = ref(false)
const showLogin = ref(false)
const showRegister = ref(false)
const selectedService = ref(null)
const selectedOrder = ref(null)

const userName = computed(() => {
  if (authStore.user?.name) return authStore.user.name
  if (authStore.user?.email) return authStore.user.email.split('@')[0]
  return 'Пользователь'
})

const activeOrders = computed(() => {
  if (!orders.value) return 0
  return orders.value.filter(o => ['pending', 'accepted'].includes(o.status)).length
})

const completedOrders = computed(() => {
  if (!orders.value) return 0
  return orders.value.filter(o => o.status === 'completed').length
})

onMounted(async () => {
  await fetchOrders()
})

async function fetchOrders() {
  loading.value = true
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.get('/api/get-customer-orders', {
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
    loading.value = false
  }
}

function openContactModal(order) {
  selectedOrder.value = order
  showContactModal.value = true
}

function closeContactModal() {
  showContactModal.value = false
  selectedOrder.value = null
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
    accepted: 'Подтверждён',
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

async function cancelOrder(orderId) {
  if (!confirm('Вы уверены что хотите отменить заказ?')) return
  
  try {
    const token = localStorage.getItem('accessToken')
    const response = await api.delete(`/api/cancel-order/${orderId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    })
    if (response.data && response.data.success) {
      alert('Заказ отменён')
      await fetchOrders()
    } else {
      alert('Ошибка отмены заказа')
    }
  } catch (error) {
    alert('Ошибка подключения к серверу')
    console.error(error)
  }
}

function openReviewForm(order) {
  selectedOrder.value = order
  showReviewForm.value = true
}

function onOrderCreated() {
  showOrderForm.value = false
  selectedService.value = null
}

function onReviewCreated() {
  showReviewForm.value = false
  selectedOrder.value = null
  fetchOrders()
}
</script>

<style scoped>
.customer-dashboard { min-height: 100vh; background: #f5f5f5; }
.dashboard-container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
.dashboard-container h1 { font-size: 32px; color: #1e293b; margin-bottom: 32px; }
.dashboard-section { background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.dashboard-section h2 { font-size: 24px; color: #1e293b; margin-bottom: 20px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
.stat-card { background: #f8fafc; padding: 24px; border-radius: 8px; text-align: center; }
.stat-number { font-size: 36px; font-weight: 700; color: #135bec; margin-bottom: 8px; }
.stat-label { color: #64748b; font-size: 14px; }
.empty, .loading { text-align: center; padding: 40px; color: #64748b; }
.orders-list { display: flex; flex-direction: column; gap: 16px; }
.order-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }
.order-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.order-header h3 { font-size: 18px; color: #1e293b; }
.order-description { color: #64748b; font-size: 14px; margin-bottom: 12px; line-height: 1.5; }
.order-info { display: flex; gap: 24px; margin-bottom: 12px; }
.info-item { display: flex; flex-direction: column; gap: 4px; }
.info-label { font-size: 12px; color: #94a3b8; }
.info-value { font-size: 14px; color: #1e293b; font-weight: 500; }

/* 🔹 УЛУЧШЕННЫЙ БЛОК ИСПОЛНИТЕЛЯ */
.worker-info { 
  background: #f8fafc; 
  padding: 16px; 
  border-radius: 8px; 
  margin-bottom: 12px; 
  border: 1px solid #e2e8f0;
}
.worker-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  width: 100%;
}
.worker-details {
  flex: 1;
}
.worker-details h4 {
  margin: 0 0 4px 0;
  font-size: 13px;
  color: #64748b;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.worker-name {
  margin: 0 0 6px 0;
  font-size: 16px;
  color: #1e293b;
  font-weight: 600;
}
.worker-phone {
  margin: 0;
  font-size: 14px;
  color: #475569;
}
.worker-phone .phone-link {
  color: #135bec;
  text-decoration: none;
  font-weight: 500;
}
.worker-phone .phone-link:hover {
  text-decoration: underline;
}
.btn-contact {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  padding: 10px 20px;
  border-radius: 8px;
  border: none;
  font-weight: 600;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.3s;
  white-space: nowrap;
}
.btn-contact:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
}

/* 🔹 МОДАЛЬНОЕ ОКНО */
.modal { 
  display: none; 
  position: fixed; 
  top: 0; 
  left: 0; 
  width: 100%; 
  height: 100%; 
  background: rgba(0,0,0,0.6); 
  backdrop-filter: blur(4px); 
  z-index: 1000; 
  align-items: center; 
  justify-content: center; 
}
.modal.active { display: flex; }
.modal-content { 
  background: white; 
  border-radius: 12px; 
  width: 90%; 
  max-width: 450px;
  overflow: hidden;
  animation: slideUp 0.3s ease-out;
}
@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
.modal-header { 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  padding: 20px 24px; 
  border-bottom: 1px solid #e2e8f0; 
}
.modal-header h2 { 
  margin: 0; 
  font-size: 1.25rem; 
  color: #1e293b; 
}
.modal-close { 
  background: none; 
  border: none; 
  font-size: 28px; 
  cursor: pointer; 
  color: #64748b;
  transition: color 0.2s;
}
.modal-close:hover {
  color: #1e293b;
}
.modal-body { 
  padding: 24px; 
}
.modal-text {
  margin: 0 0 20px 0;
  color: #475569;
  font-size: 14px;
}

/* 🔹 КНОПКИ МЕССЕНДЖЕРОВ */
.messenger-options {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.messenger-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 14px 20px;
  border-radius: 8px;
  text-decoration: none;
  color: white;
  font-weight: 600;
  font-size: 15px;
  transition: all 0.3s;
  border: none;
  cursor: pointer;
}
.messenger-btn.telegram {
  background: #0088cc;
}
.messenger-btn.telegram:hover {
  background: #0077b5;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 136, 204, 0.3);
}
.messenger-btn.phone {
  background: #10b981;
}
.messenger-btn.phone:hover {
  background: #059669;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
}
.messenger-info {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
}
.messenger-info strong {
  font-size: 15px;
}
.messenger-info span {
  font-size: 13px;
  opacity: 0.9;
}
.no-contacts {
  text-align: center;
  padding: 20px;
  color: #64748b;
  background: #f8fafc;
  border-radius: 8px;
}

.order-actions { display: flex; gap: 8px; }
.status-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
.status-pending { background: #fef3c7; color: #92400e; }
.status-accepted { background: #d1fae5; color: #065f46; }
.status-rejected { background: #fee2e2; color: #991b1b; }
.status-completed { background: #dbeafe; color: #1e40af; }
.status-cancelled { background: #e2e8f0; color: #475569; }
.btn { padding: 10px 20px; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.2s; border: none; font-family: 'Manrope', sans-serif; font-size: 14px; }
.btn-primary { background: #135bec; color: white; }
.btn-primary:hover { background: #0d4bd6; }
.btn-danger { background: #ef4444; color: white; }
.btn-danger:hover { background: #dc2626; }
</style>