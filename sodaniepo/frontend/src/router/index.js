import { createRouter, createWebHistory } from "vue-router";
import HomeView from "@/views/HomeView.vue";
import WorkerView from "@/views/WorkerView.vue";
import CustomerView from "@/views/CustomerView.vue";
import AdminView from "@/views/AdminView.vue";
import WorkerProfile from "@/views/WorkerProfile.vue";
import UserProfile from "@/views/UserProfile.vue";
import PrivacyPolicyView from "@/views/PrivacyPolicy.vue"; // 🔹 ДОБАВИТЬ

const routes = [
  { path: "/", name: "Home", component: HomeView },
  { path: "/worker", name: "Worker", component: WorkerView },
  { path: "/customer", name: "Customer", component: CustomerView },
  { path: "/admin", name: "Admin", component: AdminView },
  { path: "/profile/:id", name: "WorkerProfile", component: WorkerProfile },
  { path: "/profile/me", name: "UserProfile", component: UserProfile },
  { path: "/privacy", name: "PrivacyPolicy", component: PrivacyPolicyView }, // 🔹 ДОБАВИТЬ
];

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior() {
    return { top: 0 }; // 🔹 Автоскролл наверх при переходе
  },
});

export default router;
