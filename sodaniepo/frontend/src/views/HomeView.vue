<template>
  <div class="home">
    <Header 
      @open-login="showLogin = true" 
      @open-register="showRegister = true"
    />
    
    <section class="hero">
      <h2>Найдите лучших специалистов</h2>
      <p>Тысячи профессионалов готовы выполнить вашу работу</p>
      <div class="search-box">
        <input type="text" v-model="searchQuery" placeholder="Какую услугу вы ищете?" @keyup.enter="handleSearch">
        <button @click="handleSearch"><span class="material-symbols-outlined">search</span> Найти</button>
      </div>
    </section>
    
    <section class="about-section" id="about">
      <div class="about-container">
        <div class="about-header">
          <h2>О компании Staff Tracking</h2>
          <p>Профессиональные решения для вашего дома</p>
        </div>
        <div class="about-stats">
          <div class="stat-card"><div class="stat-icon">👷</div><div class="stat-number">5000+</div><div class="stat-label">Специалистов</div></div>
          <div class="stat-card"><div class="stat-icon">✅</div><div class="stat-number">98%</div><div class="stat-label">Отзывов</div></div>
          <div class="stat-card"><div class="stat-icon">🏆</div><div class="stat-number">10+</div><div class="stat-label">Лет опыта</div></div>
          <div class="stat-card"><div class="stat-icon">⚡</div><div class="stat-number">24/7</div><div class="stat-label">Поддержка</div></div>
        </div>
      </div>
    </section>
    
    <section class="services-section" id="services">
      <div class="section-header">
        <h3>Популярные услуги</h3>
        <div class="filters">
          <select v-model="filters.category" @change="applyFilters">
            <option value="">Все категории</option>
            <option value="construction">Строительство</option>
            <option value="repair">Ремонт</option>
            <option value="electrical">Электрика</option>
            <option value="plumbing">Сантехника</option>
          </select>
          <input type="number" v-model.number="filters.maxPrice" placeholder="Цена до" @input="applyFilters">
        </div>
      </div>
      
      <div v-if="loading" class="loading">Загрузка...</div>
      <div v-else-if="services.length === 0" class="empty"><p>Нет услуг</p></div>
      <div v-else class="services-grid">
        <ServiceCard v-for="service in filteredServices" :key="service.id" :service="service" @select="openServiceModal"/>
      </div>
    </section>
    
    <Footer />
    
    <LoginModal v-if="showLogin" v-model="showLogin" @show-register="showRegister = true"/>
    <RegisterModal v-if="showRegister" v-model="showRegister" @show-login="showLogin = true"/>
    <ServiceModal v-if="showServiceModal && selectedService" v-model="showServiceModal" :service="selectedService" @contact="openContactModal" @order="openOrderForm"/>
    <ContactModal v-if="showContactModal && selectedService" v-model="showContactModal" :service="selectedService"/>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import ServiceCard from '@/components/Services/ServiceCard.vue'
import ServiceModal from '@/components/Services/ServiceModal.vue'
import ContactModal from '@/components/Services/ContactModal.vue'
import LoginModal from '@/components/Auth/LoginModal.vue'
import RegisterModal from '@/components/Auth/RegisterModal.vue'

const authStore = useAuthStore()
const services = ref([])
const loading = ref(true)
const searchQuery = ref('')
const showLogin = ref(false)
const showRegister = ref(false)
const showServiceModal = ref(false)
const showContactModal = ref(false)
const selectedService = ref(null)
const filters = ref({ category: '', maxPrice: null })

const filteredServices = computed(() => {
  let result = services.value
  if (filters.value.category) result = result.filter(s => s.category === filters.value.category)
  if (filters.value.maxPrice) result = result.filter(s => s.price <= filters.value.maxPrice)
  return result
})

onMounted(async () => {
  await fetchServices()
  console.log('🔹 HomeView mounted')
  console.log('🔹 Auth:', localStorage.getItem('accessToken'), localStorage.getItem('user'))
})

async function fetchServices() {
  loading.value = true
  try {
    const response = await api.get('/api/get-all-services')
    if (response.data.success) services.value = response.data.services
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error)
  } finally {
    loading.value = false
  }
}

function handleSearch() { console.log('Поиск:', searchQuery.value) }
function applyFilters() { console.log('Фильтры:', filters.value) }

function openServiceModal(service) {
  selectedService.value = service
  showServiceModal.value = true
}

function openContactModal() {
  showServiceModal.value = false
  showContactModal.value = true
}

function openOrderForm(service) {
  if (!authStore.isAuthenticated) {
    alert('Войдите чтобы заказать!')
    showServiceModal.value = false
    showLogin.value = true
    return
  }
  if (authStore.userRole !== 'customer') {
    alert('Только клиенты могут заказывать!')
    return
  }
  alert('Заказ: ' + service.title)
}
</script>

<style scoped>
.home { min-height: 100vh; }
.hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 80px 40px; text-align: center; }
.hero h2 { font-size: 48px; margin-bottom: 16px; font-weight: 800; }
.hero p { font-size: 20px; margin-bottom: 32px; opacity: 0.95; }
.search-box { max-width: 700px; margin: 0 auto; display: flex; gap: 12px; }
.search-box input { flex: 1; padding: 16px 24px; border: none; border-radius: 12px; font-size: 16px; }
.search-box button { padding: 16px 32px; background: #135bec; color: white; border: none; border-radius: 12px; font-weight: 600; cursor: pointer; }
.about-section { padding: 50px 40px; background: linear-gradient(135deg, #f5f7fa 0%, #e8ecf1 100%); }
.about-container { max-width: 1200px; margin: 0 auto; }
.about-header { text-align: center; margin-bottom: 40px; }
.about-header h2 { font-size: 32px; color: #1e293b; margin-bottom: 12px; }
.about-header p { font-size: 16px; color: #64748b; }
.about-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
.stat-card { background: white; padding: 24px 20px; border-radius: 12px; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.stat-icon { font-size: 36px; margin-bottom: 12px; }
.stat-number { font-size: 28px; font-weight: 700; color: #135bec; margin-bottom: 6px; }
.stat-label { color: #64748b; font-size: 13px; font-weight: 600; }
.services-section { padding: 60px 40px; max-width: 1400px; margin: 0 auto; }
.section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
.section-header h3 { font-size: 32px; color: #1e293b; }
.filters { display: flex; gap: 12px; }
.filters select, .filters input { padding: 10px 16px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; }
.services-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 24px; }
.loading, .empty { text-align: center; padding: 60px 20px; color: #64748b; }
@media (max-width: 768px) {
  .hero h2 { font-size: 32px; }
  .services-section { padding: 40px 20px; }
}
</style>