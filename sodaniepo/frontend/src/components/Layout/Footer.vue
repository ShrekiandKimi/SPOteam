<template>
  <footer class="footer" id="contacts">
    <div class="footer-container">
      <div class="footer-content">
        <div class="footer-section">
          <h3>Staff Tracking</h3>
          <p>Находим лучших специалистов для реализации ваших проектов. Качество, надежность и профессионализм — наши главные принципы.</p>
          <div class="social-links">
            <a href="https://vk.com" target="_blank" class="social-link" title="ВКонтакте">
              <i class="fab fa-vk"></i>
            </a>
            <a href="https://t.me" target="_blank" class="social-link" title="Telegram">
              <i class="fab fa-telegram"></i>
            </a>
            <a href="https://max.ru" target="_blank" class="social-link max-link" title="MAX">
              <span>MAX</span>
            </a>
          </div>
        </div>
        
        <div class="footer-section">
          <h4>Разделы</h4>
          <ul class="footer-links">
            <li><a href="#services">Услуги</a></li>
            <li><a href="#about">О нас</a></li>
            <li><a href="#contacts">Контакты</a></li>
            <li><a href="#">Политика конфиденциальности</a></li>
          </ul>
        </div>
        
        <div class="footer-section">
          <h4>Популярные услуги</h4>
          <ul class="footer-links">
            <li><a href="#">Строительство</a></li>
            <li><a href="#">Ремонт квартир</a></li>
            <li><a href="#">Электрика</a></li>
            <li><a href="#">Сантехника</a></li>
          </ul>
        </div>
        
        <div class="footer-section">
          <h4>Контакты</h4>
          <ul class="footer-contact">
            <li>📞 +7 (999) 123-45-67</li>
            <li>✉️ info@stafftracking.ru</li>
            <li>📍 г. Москва, ул. Примерная, 123</li>
            <li>🕐 Пн-Пт: 9:00 - 20:00</li>
          </ul>
        </div>
      </div>
      
      <div class="footer-bottom">
        <p>&copy; {{ currentYear }} Staff Tracking. Все права защищены.</p>
      </div>
    </div>
  </footer>
</template>

<script setup>
import { computed } from 'vue'

const currentYear = computed(() => new Date().getFullYear())
</script>

<style scoped>
.footer { 
  background: #1e293b; 
  color: white; 
  padding: 60px 40px 0; 
}

.footer-container { 
  max-width: 1200px; 
  margin: 0 auto; 
}

.footer-content { 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
  gap: 40px; 
  margin-bottom: 40px; 
}

.footer-section h3 { 
  font-size: 24px; 
  margin-bottom: 20px; 
  color: #135bec; 
  font-weight: 700; 
}

.footer-section h4 { 
  font-size: 18px; 
  margin-bottom: 20px; 
  color: white; 
  font-weight: 600; 
}

.footer-section p { 
  color: #94a3b8; 
  line-height: 1.8; 
  font-size: 14px; 
  margin-bottom: 16px; 
}

.footer-links { 
  list-style: none; 
}

.footer-links li { 
  margin-bottom: 12px; 
}

.footer-links a { 
  color: #94a3b8; 
  text-decoration: none; 
  transition: color 0.2s; 
  font-size: 14px; 
}

.footer-links a:hover { 
  color: #135bec; 
}

.footer-contact { 
  list-style: none; 
}

.footer-contact li { 
  color: #94a3b8; 
  margin-bottom: 12px; 
  font-size: 14px; 
  display: flex; 
  align-items: center; 
  gap: 8px; 
}

.social-links { 
  display: flex; 
  gap: 12px; 
  margin-top: 20px; 
}

.social-link { 
  width: 40px; 
  height: 40px; 
  border-radius: 50%; 
  background: #135bec; 
  display: flex; 
  align-items: center; 
  justify-content: center; 
  color: white; 
  text-decoration: none; 
  font-weight: 600; 
  transition: all 0.3s; 
  font-size: 18px; 
}

.social-link.max-link { 
  font-size: 11px; 
  font-weight: 700; 
  letter-spacing: 0.5px; 
}

.social-link:hover { 
  transform: translateY(-3px); 
}

.social-link[href*="vk.com"]:hover { 
  background: #0077FF; 
}

.social-link[href*="t.me"]:hover { 
  background: #229ED9; 
}

.social-link.max-link:hover { 
  background: #FF6B00; 
}

.footer-bottom { 
  border-top: 1px solid #334155; 
  padding: 24px 0; 
  text-align: center; 
  color: #94a3b8; 
  font-size: 14px; 
}

@media (max-width: 768px) {
  .footer { 
    padding: 40px 20px 0; 
  }
}
</style>