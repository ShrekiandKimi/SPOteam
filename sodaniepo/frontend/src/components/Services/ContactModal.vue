<template>
  <div class="modal" :class="{ active: modelValue }" @click.self="closeModal">
    <div class="modal-content" style="max-width: 400px;">
      <div class="modal-header">
        <h2>Связаться с исполнителем</h2>
        <button class="modal-close" @click="closeModal">×</button>
      </div>
      
      <div class="modal-body">
        <div style="text-align: center; margin-bottom: 24px;">
          <div style="font-size: 18px; font-weight: 600; color: #1e293b; margin-bottom: 4px;">
            {{ service.worker_name || 'Исполнитель' }}
          </div>
          <div style="font-size: 14px; color: #64748b;">
            {{ service.title }}
          </div>
        </div>
        
        <!-- Telegram -->
        <a 
          v-if="service.telegram" 
          :href="telegramLink" 
          target="_blank" 
          class="contact-option telegram"
        >
          <div class="contact-icon telegram">
            <i class="fab fa-telegram"></i>
          </div>
          <div class="contact-info">
            <div>Telegram</div>
            <div>{{ service.telegram }}</div>
          </div>
        </a>
        
        <!-- MAX -->
        <a 
          v-if="service.max" 
          :href="maxLink" 
          target="_blank" 
          class="contact-option max"
        >
          <div class="contact-icon max">MAX</div>
          <div class="contact-info">
            <div>MAX</div>
            <div>{{ service.max }}</div>
          </div>
        </a>
        
        <!-- Если нет контактов -->
        <div v-if="!service.telegram && !service.max" style="text-align: center; padding: 20px; color: #64748b;">
          <p>Исполнитель не указал контакты</p>
          <p style="font-size: 13px; margin-top: 8px;">
            Свяжитесь через форму заказа
          </p>
        </div>
        
        <p style="font-size: 13px; color: #94a3b8; text-align: center; margin-top: 16px;">
          Выберите удобный способ связи
        </p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  modelValue: Boolean,
  service: {
    type: Object,
    required: true
  }
})

const emit = defineEmits(['update:modelValue'])

const telegramLink = computed(() => {
  if (!props.service.telegram) return '#'
  const username = props.service.telegram.replace('@', '')
  return `https://t.me/${username}`
})

const maxLink = computed(() => {
  if (!props.service.max) return '#'
  const phone = props.service.max.replace(/\D/g, '')
  return `https://max.ru/${phone}`
})

function closeModal() {
  emit('update:modelValue', false)
}
</script>

<style scoped>
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
  max-width: 400px; 
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

.contact-option { 
  display: flex; 
  align-items: center; 
  gap: 12px; 
  padding: 16px; 
  border-radius: 8px; 
  text-decoration: none; 
  color: #1e293b; 
  transition: all 0.2s; 
  margin-bottom: 12px; 
  cursor: pointer; 
}

.contact-option:hover { 
  transform: translateY(-2px); 
}

.contact-option.telegram { 
  background: #f0f9ff; 
}

.contact-option.telegram:hover { 
  background: #e0f2fe; 
}

.contact-option.max { 
  background: #fff7ed; 
}

.contact-option.max:hover { 
  background: #ffedd5; 
}

.contact-icon { 
  width: 40px; 
  height: 40px; 
  border-radius: 50%; 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  font-size: 20px; 
}

.contact-icon.telegram { 
  background: #229ED9; 
  color: white; 
}

.contact-icon.max { 
  background: #FF6B00; 
  color: white; 
  font-weight: 700; 
  font-size: 12px; 
}

.contact-info div:first-child { 
  font-weight: 600; 
  font-size: 14px; 
}

.contact-info div:last-child { 
  font-size: 13px; 
  color: #64748b; 
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
</style>