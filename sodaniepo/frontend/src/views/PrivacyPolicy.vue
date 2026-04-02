<template>
  <div class="privacy-container">
    <h1>Политика конфиденциальности</h1>
    <div class="privacy-content">
      <p>Дата вступления в силу: 01.04.2026</p>

      <h2>1. Общие положения</h2>
      <p>Настоящая Политика конфиденциальности определяет порядок обработки и защиты персональных данных пользователей платформы "Строительные технологии". Используя наш сайт, вы соглашаетесь с условиями данной политики.</p>

      <h2>2. Сбор информации</h2>
      <p>Мы собираем только те данные, которые необходимы для оказания услуг: имя, email, номер телефона, адрес и информацию о заказах. Платежные данные не хранятся на наших серверах.</p>

      <h2>3. Использование данных</h2>
      <p>Ваши данные используются исключительно для: обработки заказов, связи с вами, улучшения качества услуг и выполнения юридических обязательств. Мы не передаем ваши данные третьим лицам без вашего согласия.</p>

      <h2>4. Защита данных</h2>
      <p>Мы применяем современные технические и организационные меры для защиты вашей информации от несанкционированного доступа, изменения, раскрытия или уничтожения.</p>

      <h2>5. Права пользователя</h2>
      <p>Вы имеете право запросить копию своих данных, потребовать их исправления или удаления, написав на email: <a href="mailto:info@stafftracking.ru" class="contact-email">info@stafftracking.ru</a>.</p>

      <h2>6. Изменения в политике</h2>
      <p>Мы оставляем за собой право вносить изменения в настоящую политику. Актуальная версия всегда доступна на этой странице.</p>

      <router-link to="/" class="btn btn-primary back-btn">← Вернуться на главную</router-link>
    </div>
  </div>
  <Footer />
</template>

<script setup>
import Footer from '@/components/Layout/Footer.vue'
</script>

<style scoped>
.privacy-container {
  max-width: 900px;
  margin: 0 auto;
  padding: 60px 20px;
  min-height: calc(100vh - 80px);
}
h1 {
  font-size: 36px;
  color: #1e293b;
  margin-bottom: 32px;
  font-weight: 700;
}
.privacy-content {
  background: white;
  padding: 40px;
  border-radius: 12px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  line-height: 1.8;
  color: #475569;
}
h2 {
  font-size: 22px;
  color: #1e293b;
  margin-top: 32px;
  margin-bottom: 12px;
  font-weight: 600;
}
p { margin-bottom: 16px; }
.contact-email {
  color: #135bec;
  text-decoration: none;
  font-weight: 500;
}
.contact-email:hover { text-decoration: underline; }
.back-btn {
  margin-top: 40px;
  display: inline-block;
}
@media (max-width: 768px) {
  .privacy-container { padding: 40px 16px; }
  .privacy-content { padding: 24px; }
  h1 { font-size: 28px; }
}
</style>