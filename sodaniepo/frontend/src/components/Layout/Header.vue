<template>
  <header class="header">
    <div class="logo" @click="goHome" style="cursor: pointer;">
      <span class="material-symbols-outlined">engineering</span>
      <h1>Строительные технологии</h1>
    </div>
    
    <!-- Навигация на главной странице -->
    <nav class="nav-links" v-if="isHomePage">
      <a href="#about">О нас</a>
      <a href="#services">Актуальные услуги</a>
      <a href="#contacts">Контакты</a>
    </nav>
    
    <!-- Навигация в кабинетах -->
    <nav class="nav-links" v-else>
      <a @click="goHome" style="cursor: pointer;">На главную</a>
    </nav>
    
    <!-- Кнопки для гостей -->
    <div class="auth-buttons" v-if="!authStore.isAuthenticated">
      <button class="btn btn-outline" @click="emit('open-login')">Войти</button>
      <button class="btn btn-primary" @click="emit('open-register')">Регистрация</button>
    </div>
    
    <!-- Меню пользователя -->
    <div class="user-menu" v-else>
      <div class="user-info" @click="toggleDropdown">
        <span class="user-avatar">👤</span>
        <span class="user-name">{{ userName }}</span>
        <span class="dropdown-arrow" :class="{ active: dropdownOpen }">▼</span>
      </div>
      
      <div class="user-dropdown" :class="{ active: dropdownOpen }">
        <!-- 🔹 ССЫЛКА ПО РОЛИ (но везде одинаковый текст) -->
        <router-link 
          :to="profileLink"
          class="dropdown-item"
          @click="dropdownOpen = false"
        >
          <span class="dropdown-icon">👤</span>
          <span class="dropdown-text">Мой профиль</span>
        </router-link>
        
        <div class="dropdown-divider"></div>
        <a href="#" class="dropdown-item logout" @click.prevent="handleLogout">
          <span class="dropdown-icon">🚪</span>
          <span class="dropdown-text">Выйти</span>
        </a>
      </div>
    </div>
  </header>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const emit = defineEmits(['open-login', 'open-register'])
const authStore = useAuthStore()
const dropdownOpen = ref(false)

// Проверка: на главной ли мы странице
const isHomePage = computed(() => route.path === '/')

// Имя пользователя
const userName = computed(() => {
  if (authStore.user?.name) return authStore.user.name
  if (authStore.user?.email) return authStore.user.email.split('@')[0]
  return 'Пользователь'
})

// 🔹 ССЫЛКА ПО РОЛИ
const profileLink = computed(() => {
  const roleLinks = {
    admin: '/admin',
    worker: '/worker',
    customer: '/customer'
  }
  return roleLinks[authStore.user?.role] || '/'
})

// Переход на главную
function goHome() {
  router.push('/')
}

// Открыть/закрыть выпадающее меню
function toggleDropdown() {
  dropdownOpen.value = !dropdownOpen.value
}

// Выход из аккаунта
function handleLogout() {
  authStore.logout()
  dropdownOpen.value = false
  router.push('/')
}

// Закрытие меню при клике вне
function handleClickOutside(event) {
  if (!event.target.closest('.user-menu')) {
    dropdownOpen.value = false
  }
}

// Слушатель кликов при монтировании
onMounted(() => {
  document.addEventListener('click', handleClickOutside)
})

// Очистка слушателя при размонтировании
onUnmounted(() => {
  document.removeEventListener('click', handleClickOutside)
})
</script>

<style scoped>
.header { 
  background: white; 
  padding: 16px 40px; 
  display: flex; 
  justify-content: space-between; 
  align-items: center; 
  box-shadow: 0 2px 8px rgba(0,0,0,0.1); 
  position: sticky; 
  top: 0; 
  z-index: 100; 
}
.logo { 
  display: flex; 
  align-items: center; 
  gap: 12px; 
}
.logo .material-symbols-outlined { 
  font-size: 36px; 
  color: #135bec; 
}
.logo h1 { 
  font-size: 24px; 
  color: #1e293b; 
  font-weight: 700; 
}
.nav-links { 
  display: flex; 
  gap: 24px; 
  align-items: center; 
}
.nav-links a { 
  text-decoration: none; 
  color: #475569; 
  font-weight: 500; 
  transition: color 0.2s; 
  cursor: pointer;
}
.nav-links a:hover { 
  color: #135bec; 
}
.auth-buttons { 
  display: flex; 
  gap: 12px; 
  align-items: center; 
}
.user-menu { 
  position: relative; 
  display: flex !important; 
  align-items: center; 
}
.user-info { 
  display: flex !important; 
  align-items: center; 
  gap: 8px; 
  padding: 8px 16px; 
  background: #f8fafc; 
  border-radius: 8px; 
  cursor: pointer; 
  transition: all 0.2s; 
  border: 2px solid #e2e8f0; 
}
.user-info:hover { 
  background: #f1f5f9; 
  border-color: #135bec; 
}
.user-avatar { 
  font-size: 20px; 
}
.user-name { 
  font-weight: 600; 
  color: #1e293b; 
  font-size: 14px; 
}
.dropdown-arrow { 
  font-size: 10px; 
  color: #64748b; 
  transition: transform 0.2s; 
}
.dropdown-arrow.active { 
  transform: rotate(180deg); 
}
.user-dropdown { 
  position: absolute; 
  top: calc(100% + 8px); 
  right: 0; 
  background: white; 
  border-radius: 8px; 
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15); 
  min-width: 240px; 
  display: none; 
  z-index: 1001; 
  overflow: hidden; 
}
.user-dropdown.active { 
  display: block !important; 
}
.dropdown-item { 
  display: flex; 
  align-items: center; 
  gap: 12px; 
  padding: 12px 16px; 
  color: #475569; 
  text-decoration: none; 
  transition: all 0.2s; 
  font-size: 14px; 
  cursor: pointer; 
}
.dropdown-item:hover { 
  background: #f8fafc; 
  color: #135bec; 
}
.dropdown-item.logout:hover { 
  background: #fee2e2; 
  color: #dc2626; 
}
.dropdown-divider {
  height: 1px;
  background: #e2e8f0;
  margin: 4px 0;
}
.dropdown-icon {
  font-size: 18px;
}
.dropdown-text {
  flex: 1;
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
}
@media (max-width: 768px) {
  .nav-links { display: none; }
  .header { padding: 16px 20px; }
}
</style>