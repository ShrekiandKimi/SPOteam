import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import AdminView from '../views/AdminView.vue'
import CustomerView from '../views/CustomerView.vue'
import WorkerView from '../views/WorkerView.vue'

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
      component: AdminView,
      meta: { requiresAuth: true, role: 'admin' }
    },
    {
      path: '/customer',
      name: 'customer',
      component: CustomerView,
      meta: { requiresAuth: true, role: 'customer' }
    },
    {
      path: '/worker',
      name: 'worker',
      component: WorkerView,
      meta: { requiresAuth: true, role: 'worker' }
    }
  ]
})

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