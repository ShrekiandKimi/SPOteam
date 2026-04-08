<template>
  <div class="worker-profile">
    <Header @open-login="showLogin = true" @open-register="showRegister = true" />
    
    <div class="profile-container">
      <!-- 🔹 ЗАГОЛОВОК ПРОФИЛЯ -->
      <div class="profile-header">
        <div class="profile-avatar">
          <div class="avatar-placeholder">{{ workerName.charAt(0).toUpperCase() }}</div>
        </div>
        <div class="profile-info">
          <h1>{{ workerName }}</h1>
          <div class="profile-meta">
            <span class="rating-badge" v-if="averageRating > 0">
              ⭐ {{ averageRating.toFixed(1) }} ({{ reviews.length }} отзывов)
            </span>
            <span class="role-badge">Исполнитель</span>
          </div>
          <div class="profile-contacts" v-if="workerPhone || workerTelegram">
            <a v-if="workerPhone" :href="'tel:' + workerPhone" class="contact-link">
              📞 {{ workerPhone }}
            </a>
            <a v-if="workerTelegram" :href="'https://t.me/' + workerTelegram.replace('@', '')" 
               target="_blank" class="contact-link">
              ✈ {{ workerTelegram }}
            </a>
          </div>
          <div v-if="workerBio" class="worker-bio">
            <p>{{ workerBio }}</p>
          </div>
        </div>
      </div>
      
      <!-- 🔹 СТАТИСТИКА -->
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-number">{{ services.length }}</div>
          <div class="stat-label">Услуг</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">{{ reviews.length }}</div>
          <div class="stat-label">Отзывов</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">{{ averageRating > 0 ? averageRating.toFixed(1) : 'N/A' }}</div>
          <div class="stat-label">Рейтинг</div>
        </div>
      </div>
      
      <!-- 🔹 УСЛУГИ -->
      <section class="profile-section">
        <h2>Услуги</h2>
        <div v-if="loadingServices" class="loading">Загрузка...</div>
        <div v-else-if="services.length === 0" class="empty">Нет услуг</div>
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
              <span>Гарантия: {{ service.guarantee }} мес</span>
            </div>
          </div>
        </div>
      </section>
      
      <!-- 🔹 ОТЗЫВЫ -->
      <section class="profile-section">
        <h2>Отзывы клиентов</h2>
        <div v-if="loadingReviews" class="loading">Загрузка...</div>
        <div v-else-if="reviews.length === 0" class="empty">Пока нет отзывов</div>
        <div v-else class="reviews-list">
          <div v-for="review in reviews" :key="review.id" class="review-card">
            <div class="review-header">
              <div class="review-author">
                <strong>{{ review.customer_name }}</strong>
                <span class="review-date">{{ formatDate(review.created_at) }}</span>
              </div>
              <div class="review-rating">
                <span v-for="i in 5" :key="i" 
                      :class="['star', i <= review.rating ? 'active' : '']">
                  ★
                </span>
              </div>
            </div>
            <p v-if="review.comment" class="review-comment">{{ review.comment }}</p>
          </div>
        </div>
      </section>
    </div>
    
    <Footer />
    
    <LoginModal 
      v-if="showLogin"
      v-model="showLogin"
    />
    
    <RegisterModal 
      v-if="showRegister"
      v-model="showRegister"
      @show-login="showLogin = true; showRegister = false"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import api from '@/api'
import Header from '@/components/Layout/Header.vue'
import Footer from '@/components/Layout/Footer.vue'
import LoginModal from '@/components/Auth/LoginModal.vue'
import RegisterModal from '@/components/Auth/RegisterModal.vue'

const route = useRoute()
const workerId = computed(() => parseInt(route.params.id))

// 🔹 ИСПРАВЛЕНО: объявлены все переменные профиля
const workerName = ref('Исполнитель')
const workerPhone = ref('')
const workerBio = ref('') // 🔹 ДОБАВЛЕНО

const services = ref([])
const reviews = ref([])
const loadingServices = ref(true)
const loadingReviews = ref(true)
const showLogin = ref(false)
const showRegister = ref(false)

const averageRating = computed(() => {
  if (reviews.value.length === 0) return 0
  const sum = reviews.value.reduce((acc, r) => acc + r.rating, 0)
  return sum / reviews.value.length
})

// 🔹 ИСПРАВЛЕНО: правильный эндпоинт и парсинг ответа
async function fetchWorkerPublicInfo() {
  try {
    const response = await api.get(`/api/get-public-profile/${workerId.value}`)
    if (response.data?.success && response.data.worker) {
      const w = response.data.worker
      workerName.value = w.name || 'Исполнитель'
      workerPhone.value = w.phone || ''
      workerBio.value = w.bio || '' // 🔹 ТЕПЕРЬ БЕРЁМ BIO ИЗ ПРАВИЛЬНОГО ОБЪЕКТА
    }
  } catch (error) {
    console.error('Ошибка загрузки публичного профиля:', error)
  }
}

onMounted(async () => {
  await fetchWorkerPublicInfo() // 🔹 ЗАГРУЖАЕМ ПРОФИЛЬ ПЕРВЫМ
  await fetchServices()
  await fetchReviews()
})

async function fetchServices() {
  loadingServices.value = true
  try {
    const response = await api.get('/api/get-all-services')
    if (response.data?.success) {
      services.value = response.data.services.filter(s => s.worker_id === workerId.value) || []
    }
  } catch (error) {
    console.error('Ошибка загрузки услуг:', error)
  } finally {
    loadingServices.value = false
  }
}

async function fetchReviews() {
  loadingReviews.value = true
  try {
    const response = await api.get(`/api/get-worker-reviews/${workerId.value}`)
    if (response.data?.success) {
      reviews.value = response.data.reviews || []
    }
  } catch (error) {
    console.error('Ошибка загрузки отзывов:', error)
  } finally {
    loadingReviews.value = false
  }
}

function getCategoryName(category) {
  const names = { construction: 'Строительство', repair: 'Ремонт', electrical: 'Электрика', plumbing: 'Сантехника' }
  return names[category] || category
}

function formatDate(date) {
  if (!date) return ''
  return new Date(date).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' })
}
</script>

<style scoped>
.worker-profile { min-height: 100vh; background: #f5f5f5; }
.profile-container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }





.worker-bio {
  background: #f8fafc;
  padding: 16px;
  border-radius: 8px;
  margin-top: 16px;
  color: #475569;
  line-height: 1.6;
  font-size: 14px;
  white-space: pre-wrap; /* Сохраняет переносы строк из textarea */
}


/* 🔹 ЗАГОЛОВОК */


.profile-header {
  background: white;
  border-radius: 12px;
  padding: 32px;
  margin-bottom: 24px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  display: flex;
  gap: 24px;
  align-items: center;
}
.profile-avatar .avatar-placeholder {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 48px;
  font-weight: 700;
}
.profile-info h1 {
  margin: 0 0 12px 0;
  font-size: 32px;
  color: #1e293b;
}
.profile-meta {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
  flex-wrap: wrap;
}
.rating-badge {
  background: linear-gradient(135deg, #fbbf24 0%, #f59e0b 100%);
  color: white;
  padding: 6px 12px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 14px;
}
.role-badge {
  background: #e0e7ff;
  color: #4f46e5;
  padding: 6px 12px;
  border-radius: 6px;
  font-weight: 600;
  font-size: 14px;
}
.profile-contacts {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}
.contact-link {
  color: #135bec;
  text-decoration: none;
  font-weight: 500;
}
.contact-link:hover {
  text-decoration: underline;
}

/* 🔹 СТАТИСТИКА */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.stat-card {
  background: white;
  padding: 24px;
  border-radius: 12px;
  text-align: center;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
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

/* 🔹 СЕКЦИИ */
.profile-section {
  background: white;
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
.profile-section h2 {
  margin: 0 0 20px 0;
  font-size: 24px;
  color: #1e293b;
}

/* 🔹 УСЛУГИ */
.services-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
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
  flex-wrap: wrap;
  gap: 12px;
  font-size: 13px;
  color: #475569;
}

/* 🔹 ОТЗЫВЫ */
.reviews-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.review-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 16px;
  background: #f8fafc;
}
.review-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}
.review-author {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.review-author strong {
  color: #1e293b;
}
.review-date {
  font-size: 12px;
  color: #94a3b8;
}
.review-rating {
  display: flex;
  gap: 2px;
}
.star {
  color: #e2e8f0;
  font-size: 18px;
}
.star.active {
  color: #fbbf24;
}
.review-comment {
  margin: 0;
  color: #475569;
  line-height: 1.6;
}

.empty, .loading {
  text-align: center;
  padding: 40px;
  color: #64748b;
}

@media (max-width: 768px) {
  .profile-header {
    flex-direction: column;
    text-align: center;
  }
  .profile-meta, .profile-contacts {
    justify-content: center;
  }
}
</style>