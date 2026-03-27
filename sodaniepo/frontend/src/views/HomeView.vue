<template>
  <div class="home">
    <Header 
      @open-login="showLogin = true" 
      @open-register="showRegister = true"
    />
    
    <!-- Hero Section -->
    <section class="hero">
      <h2>Найдите лучших специалистов</h2>
      <p>Тысячи профессионалов готовы выполнить вашу работу</p>
      <div class="search-box">
        <input 
          type="text" 
          v-model="searchQuery" 
          placeholder="Какую услугу вы ищете?"
          @keyup.enter="handleSearch"
        >
        <button @click="handleSearch">
          <span class="material-symbols-outlined">search</span>
          Найти
        </button>
      </div>
    </section>
    
    <!-- About Section -->
    <section class="about-section" id="about">
      <div class="about-container">
        <div class="about-header">
          <h2>О компании Staff Tracking</h2>
          <p>Профессиональные решения для вашего дома: находим лучших мастеров для воплощения ваших идей</p>
        </div>
        <div class="about-stats">
          <div class="stat-card">
            <div class="stat-icon">👷</div>
            <div class="stat-number">5000+</div>
            <div class="stat-label">Проверенных специалистов</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">✅</div>
            <div class="stat-number">98%</div>
            <div class="stat-label">Положительных отзывов</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">🏆</div>
            <div class="stat-number">10+</div>
            <div class="stat-label">Лет на рынке</div>
          </div>
          <div class="stat-card">
            <div class="stat-icon">⚡</div>
            <div class="stat-number">24/7</div>
            <div class="stat-label">Поддержка</div>
          </div>
        </div>
        <div class="about-content">
          <div class="about-text">
            <h3>Почему выбирают нас?</h3>
            <p>Staff Tracking — это современная платформа для поиска квалифицированных специалистов в сфере строительства, ремонта и благоустройства.</p>
            <div class="about-features">
              <div class="feature-item">
                <span class="feature-icon">✓</span>
                <span>Проверенные специалисты</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">✓</span>
                <span>Гарантия качества</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">✓</span>
                <span>Прозрачные цены</span>
              </div>
              <div class="feature-item">
                <span class="feature-icon">✓</span>
                <span>Быстрый подбор</span>
              </div>
            </div>
          </div>
          <div class="about-image">
            <div class="image-placeholder">
              <span class="material-symbols-outlined">groups</span>
            </div>
          </div>
        </div>
      </div>
    </section>
    
    <!-- Services Section -->
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
          <input 
            type="number" 
            v-model.number="filters.maxPrice" 
            placeholder="Цена до"
            @input="applyFilters"
          >
        </div>
      </div>
      
      <div v-if="loading" class="loading">Загрузка услуг...</div>
      
      <div v-else-if="!services || services.length === 0" class="empty">
        <p>Пока нет доступных услуг</p>
        <p style="font-size: 14px; color: #64748b; margin-top: 8px;">
          Исполнители скоро добавят свои услуги
        </p>
      </div>
      
      <div v-else class="services-grid">
        <ServiceCard 
          v-for="service in filteredServices" 
          :key="service.id"
          :service="service"
          @select="openServiceModal"
        />
      </div>
    </section>
    
    <Footer />
    
    <!-- Модальные окна -->
    <LoginModal 
      v-if="showLogin" 
      v-model="showLogin"
      @show-register="showRegister = true"
    />
    
    <RegisterModal 
      v-if="showRegister" 
      v-model="showRegister"
      @show-login="showLogin = true"
    />
    
    <OrderForm 
      v-if="showOrderForm"
      v-model="showOrderForm"
      :service="selectedService"
      @created="onOrderCreated"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import ServiceCard from '@/components/Services/ServiceCard.vue'
import LoginModal from '@/components/Auth/LoginModal.vue'
import RegisterModal from '@/components/Auth/RegisterModal.vue'
import OrderForm from '@/components/Services/OrderForm.vue'

const authStore = useAuthStore()

const services = ref([])
const loading = ref(true)
const searchQuery = ref('')
const showLogin = ref(false)
const showRegister = ref(false)
const showOrderForm = ref(false)
const selectedService = ref(null)

const filters = ref({
  category: '',
  maxPrice: null
})

const filteredServices = computed(() => {
  let result = services.value || []
  
  if (filters.value.category) {
    result = result.filter(s => s.category === filters.value.category)
  }
  if (filters.value.maxPrice) {
    result = result.filter(s => s.price <= filters.value.maxPrice)
  }
  
  return result
})

onMounted(async () => {
  await fetchServices()
})

async function fetchServices() {
  loading.value = true
  try {
    const response = await api.get('/api/get-all-services')
    if (response.data && response.data.success) {
      services.value = response.data.services || []
      console.log('Загружено услуг:', services.value.length)
    } else {
      services.value = []
    }
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error)
    services.value = []
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  console.log('Поиск:', searchQuery.value)
}

function applyFilters() {
  console.log('Фильтры:', filters.value)
}

function openServiceModal(service) {
  if (!authStore.isAuthenticated) {
    alert('Войдите чтобы заказать услугу')
    showLogin.value = true
    return
  }
  if (authStore.user?.role !== 'customer') {
    alert('Только клиенты могут заказывать услуги')
    return
  }
  console.log('Открытие услуги:', service)
  selectedService.value = service
  showOrderForm.value = true
}

function onOrderCreated() {
  showOrderForm.value = false
  selectedService.value = null
}
</script>

<style scoped>
.home {
  min-height: 100vh;
}

.hero { 
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
  color: white; 
  padding: 80px 40px; 
  text-align: center; 
}

.hero h2 { 
  font-size: 48px; 
  margin-bottom: 16px; 
  font-weight: 800; 
}

.hero p { 
  font-size: 20px; 
  margin-bottom: 32px; 
  opacity: 0.95; 
}

.search-box { 
  max-width: 700px; 
  margin: 0 auto; 
  display: flex; 
  gap: 12px; 
}

.search-box input { 
  flex: 1; 
  padding: 16px 24px; 
  border: none; 
  border-radius: 12px; 
  font-size: 16px; 
  font-family: 'Manrope', sans-serif; 
}

.search-box button { 
  padding: 16px 32px; 
  background: #135bec; 
  color: white; 
  border: none; 
  border-radius: 12px; 
  font-weight: 600; 
  cursor: pointer; 
  font-size: 16px; 
}

.about-section { 
  padding: 50px 40px; 
  background: linear-gradient(135deg, #f5f7fa 0%, #e8ecf1 100%); 
}

.about-container { 
  max-width: 1200px; 
  margin: 0 auto; 
}

.about-header { 
  text-align: center; 
  margin-bottom: 40px; 
}

.about-header h2 { 
  font-size: 32px; 
  color: #1e293b; 
  margin-bottom: 12px; 
  font-weight: 700; 
}

.about-header p { 
  font-size: 16px; 
  color: #64748b; 
  max-width: 700px; 
  margin: 0 auto; 
  line-height: 1.5; 
}

.about-stats { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
  gap: 20px; 
  margin-bottom: 40px; 
}

.stat-card { 
  background: white; 
  padding: 24px 20px; 
  border-radius: 12px; 
  text-align: center; 
  box-shadow: 0 2px 8px rgba(0,0,0,0.08); 
  transition: all 0.3s; 
}

.stat-card:hover { 
  transform: translateY(-3px); 
  box-shadow: 0 4px 16px rgba(0,0,0,0.12); 
}

.stat-icon { 
  font-size: 36px; 
  margin-bottom: 12px; 
}

.stat-number { 
  font-size: 28px; 
  font-weight: 700; 
  color: #135bec; 
  margin-bottom: 6px; 
}

.stat-label { 
  color: #64748b; 
  font-size: 13px; 
  font-weight: 600; 
}

.about-content { 
  display: grid; 
  grid-template-columns: 1fr 1fr; 
  gap: 40px; 
  align-items: center; 
}

.about-text h3 { 
  font-size: 24px; 
  color: #1e293b; 
  margin-bottom: 16px; 
  font-weight: 700; 
}

.about-text p { 
  color: #475569; 
  line-height: 1.6; 
  margin-bottom: 20px; 
  font-size: 15px; 
}

.about-features { 
  display: flex; 
  flex-direction: column; 
  gap: 10px; 
}

.feature-item { 
  display: flex; 
  align-items: center; 
  gap: 10px; 
  color: #1e293b; 
  font-size: 14px; 
}

.feature-icon { 
  width: 22px; 
  height: 22px; 
  background: #135bec; 
  color: white; 
  border-radius: 50%; 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  font-weight: bold; 
  flex-shrink: 0; 
  font-size: 12px; 
}

.about-image { 
  display: flex; 
  justify-content: center; 
  align-items: center; 
}

.image-placeholder { 
  width: 100%; 
  max-width: 350px; 
  height: 250px; 
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
  border-radius: 12px; 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  box-shadow: 0 12px 40px rgba(102, 126, 234, 0.25); 
}

.image-placeholder .material-symbols-outlined { 
  font-size: 80px; 
  color: white; 
  opacity: 0.9; 
}

.services-section { 
  padding: 60px 40px; 
  max-width: 1400px; 
  margin: 0 auto; 
}

.section-header { 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  margin-bottom: 32px; 
}

.section-header h3 { 
  font-size: 32px; 
  color: #1e293b; 
}

.filters { 
  display: flex; 
  gap: 12px; 
}

.filters select, 
.filters input { 
  padding: 10px 16px; 
  border: 1px solid #e2e8f0; 
  border-radius: 8px; 
  font-size: 14px; 
}

.services-grid { 
  display: grid; 
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); 
  gap: 24px; 
}

.loading, .empty {
  text-align: center;
  padding: 60px 20px;
  color: #64748b;
  font-size: 16px;
}

@media (max-width: 768px) {
  .about-content { 
    grid-template-columns: 1fr; 
  }
  
  .about-header h2 { 
    font-size: 26px; 
  }
  
  .hero h2 { 
    font-size: 32px; 
  }
  
  .services-section { 
    padding: 40px 20px; 
  }
}
</style>