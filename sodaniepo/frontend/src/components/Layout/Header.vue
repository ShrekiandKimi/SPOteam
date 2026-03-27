<template>
  <header class="header">
    <div class="logo">
      <span class="material-symbols-outlined">engineering</span>
      <h1>Staff Tracking</h1>
    </div>
    
    <nav class="nav-links">
      <a href="#services">Услуги</a>
      <a href="#about">О нас</a>
      <a href="#contacts">Контакты</a>
    </nav>
    
    <div class="auth-buttons" v-if="!authStore.isAuthenticated">
      <button class="btn btn-outline" @click="emit('open-login')">Войти</button>
      <button class="btn btn-primary" @click="emit('open-register')">Регистрация</button>
    </div>
    
    <div class="user-menu" v-else>
      <div class="user-info" @click="toggleDropdown">
        <span class="user-avatar">👤</span>
        <span class="user-name">{{ authStore.userName }}</span>
        <span class="dropdown-arrow" :class="{ active: dropdownOpen }">▼</span>
      </div>
      
      <div class="user-dropdown" :class="{ active: dropdownOpen }">
        <a :href="dashboardLink" class="dropdown-item">{{ dashboardText }}</a>
        <a href="#" class="dropdown-item" @click.prevent="handleLogout">🚪 Выйти</a>
      </div>
    </div>
  </header>
</template>

<script setup>
import { ref, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const authStore = useAuthStore()
const router = useRouter()
const emit = defineEmits(['open-login', 'open-register'])

const dropdownOpen = ref(false)

const dashboardLink = computed(() => {
  const routes = {
    admin: '/admin',
    customer: '/customer',
    worker: '/worker'
  }
  return routes[authStore.userRole] || '/'
})

const dashboardText = computed(() => {
  const texts = {
    admin: '🏗️ Панель администратора',
    customer: '📋 Мои заказы',
    worker: '💼 Мой кабинет'
  }
  return texts[authStore.userRole] || '📋 Кабинет'
})

function toggleDropdown() {
  dropdownOpen.value = !dropdownOpen.value
}

function handleLogout() {
  authStore.logout()
  router.push('/')
  dropdownOpen.value = false
}

// Закрытие dropdown при клике вне
import { onMounted, onUnmounted } from 'vue'

function handleClickOutside(event) {
  if (!event.target.closest('.user-menu')) {
    dropdownOpen.value = false
  }
}

onMounted(() => {
  document.addEventListener('click', handleClickOutside)
})

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
  gap: 32px; 
  align-items: center; 
}

.nav-links a { 
  text-decoration: none; 
  color: #475569; 
  font-weight: 500; 
  transition: color 0.2s; 
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
}

.user-info { 
  display: flex; 
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
  min-width: 200px; 
  display: none; 
  z-index: 1001; 
  overflow: hidden; 
}

.user-dropdown.active { 
  display: block; 
  animation: slideIn 0.2s ease; 
}

.dropdown-item { 
  display: flex; 
  align-items: center; 
  gap: 10px; 
  padding: 12px 16px; 
  color: #475569; 
  text-decoration: none; 
  transition: all 0.2s; 
  font-size: 14px; 
}

.dropdown-item:hover { 
  background: #f8fafc; 
  color: #135bec; 
}

.dropdown-item:first-child { 
  border-bottom: 1px solid #f1f5f9; 
}

@keyframes slideIn { 
  from { 
    transform: translateY(-20px); 
    opacity: 0; 
  } 
  to { 
    transform: translateY(0); 
    opacity: 1; 
  } 
}

@media (max-width: 768px) {
  .nav-links { 
    display: none; 
  }
  
  .header { 
    padding: 16px 20px; 
  }
}
</style>