import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '@/views/HomeView.vue'
import WorkerView from '@/views/WorkerView.vue'
import CustomerView from '@/views/CustomerView.vue'
import AdminView from '@/views/AdminView.vue'
import WorkerProfile from '@/views/WorkerProfile.vue'
import UserProfile from '@/views/UserProfile.vue'

const routes = [
  { path: '/', name: 'Home', component: HomeView },
  { path: '/worker', name: 'Worker', component: WorkerView },
  { path: '/customer', name: 'Customer', component: CustomerView },
  { path: '/admin', name: 'Admin', component: AdminView },
  { path: '/profile/:id', name: 'WorkerProfile', component: WorkerProfile },
  { path: '/profile/me', name: 'UserProfile', component: UserProfile },
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router