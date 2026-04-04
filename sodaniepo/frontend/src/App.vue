<template>
  <div id="app">
    <router-view />
  </div>
</template>

<script setup>
import { onMounted, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const authStore = useAuthStore()
const router = useRouter()


</script>

<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Manrope', sans-serif;
  background: #f5f5f5;
  min-height: 100vh;
}

html {
  scroll-behavior: smooth;
}

#app {
  min-height: 100vh;
}

/* ===== UTILITY CLASSES ===== */
.btn {
  padding: 10px 20px;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  font-family: 'Manrope', sans-serif;
  font-size: 14px;
  text-decoration: none;
  display: inline-block;
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
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(19, 91, 236, 0.3);
}

.btn-success {
  background: #10b981;
  color: white;
}

.btn-success:hover {
  background: #059669;
}

/* ===== MODAL ===== */
.modal {
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  align-items: center;
  justify-content: center;
}

.modal.active {
  display: flex;
}

.modal-content {
  background: white;
  border-radius: 12px;
  width: 90%;
  max-width: 500px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
  animation: slideIn 0.3s ease;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px 24px;
  border-bottom: 1px solid #e2e8f0;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.25rem;
  color: #1e293b;
}

.modal-close {
  background: none;
  border: none;
  font-size: 28px;
  cursor: pointer;
  color: #64748b;
  line-height: 1;
  padding: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  transition: all 0.2s;
}

.modal-close:hover {
  background: #f1f5f9;
  color: #1e293b;
}

.modal-body {
  padding: 24px;
}

/* ===== FORM ===== */
.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  color: #475569;
  font-size: 14px;
}

.form-group input,
.form-group textarea,
.form-group select {
  width: 100%;
  padding: 12px;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  font-size: 14px;
  font-family: 'Manrope', sans-serif;
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
  outline: none;
  border-color: #135bec;
  box-shadow: 0 0 0 3px rgba(19, 91, 236, 0.1);
}

/* ===== ROLE SELECTOR ===== */
.role-selector {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 12px;
  margin-top: 8px;
}

.role-option {
  padding: 16px 12px;
  border: 2px solid #e2e8f0;
  border-radius: 8px;
  cursor: pointer;
  text-align: center;
  transition: all 0.2s;
}

.role-option:hover {
  border-color: #135bec;
  background: #f8fafc;
}

.role-option.selected {
  border-color: #135bec;
  background: #eff6ff;
}

.role-option input {
  margin-right: 8px;
}

.role-option .role-title {
  font-weight: 600;
  display: block;
  margin-top: 8px;
  font-size: 14px;
}

.role-option .role-desc {
  font-size: 11px;
  color: #64748b;
  margin-top: 4px;
  display: block;
}

/* ===== ANIMATIONS ===== */
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

/* ===== LOADING ===== */
.loading {
  text-align: center;
  padding: 60px 20px;
  color: #64748b;
  font-size: 16px;
}

.empty {
  text-align: center;
  padding: 60px 20px;
  color: #64748b;
}

/* ===== MATERIAL ICONS ===== */
.material-symbols-outlined {
  font-variation-settings:
    'FILL' 0,
    'wght' 400,
    'GRAD' 0,
    'opsz' 24;
}
</style>