import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '@/views/HomeView.vue'
import WorkerView from '@/views/WorkerView.vue'
import CustomerView from '@/views/CustomerView.vue'
import AdminView from '@/views/AdminView.vue'

const routes = [
  { path: '/', name: 'home', component: HomeView },
  { path: '/worker', name: 'worker', component: WorkerView },
  { path: '/customer', name: 'customer', component: CustomerView },
  { path: '/admin', name: 'admin', component: AdminView }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router