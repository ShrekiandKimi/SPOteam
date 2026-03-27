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
          <span class="material-symbols-outlined" style="vertical-align: middle;">search</span>
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
      
      <div class="services-grid">
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
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import ServiceCard from '@/components/Services/ServiceCard.vue'
import LoginModal from '@/components/Auth/LoginModal.vue'
import RegisterModal from '@/components/Auth/RegisterModal.vue'
import { useServices } from '@/composables/useServices'

const { services, loading, fetchServices } = useServices()

const showLogin = ref(false)
const showRegister = ref(false)
const searchQuery = ref('')

const filters = ref({
  category: '',
  maxPrice: null
})

const filteredServices = computed(() => {
  let result = services.value
  
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

function handleSearch() {
  // Логика поиска
  console.log('Search:', searchQuery.value)
}

function applyFilters() {
  // Фильтрация работает через computed
}

function openServiceModal(service) {
  console.log('Open service:', service)
  // Здесь будет открытие модалки услуги
}
</script>