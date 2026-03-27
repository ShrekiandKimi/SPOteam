import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView
    },
    {
      path: '/admin',
      name: 'admin',
      component: () => import('../views/AdminView.vue'),
      meta: { requiresAuth: true, role: 'admin' }
    },
    {
      path: '/customer',
      name: 'customer',
      component: () => import('../views/CustomerView.vue'),
      meta: { requiresAuth: true, role: 'customer' }
    },
    {
      path: '/worker',
      name: 'worker',
      component: () => import('../views/WorkerView.vue'),
      meta: { requiresAuth: true, role: 'worker' }
    }
  ]
})

// Глобальная защита маршрутов
router.beforeEach((to, from, next) => {
  const token = localStorage.getItem('accessToken')
  const role = localStorage.getItem('role')
  
  if (to.meta.requiresAuth && !token) {
    return next('/')
  }
  
  if (to.meta.role && role !== to.meta.role) {
    return next('/')
  }
  
  next()
})

export default router