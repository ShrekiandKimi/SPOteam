// ===== МОДАЛЬНЫЕ ОКНА =====

function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

// ===== КОНТАКТЫ ИСПОЛНИТЕЛЯ =====

function openContactModal(service) {
  if (!service) return;
  
  // Проверяем, есть ли контакты
  if (!service.telegram && !service.max) {
    alert(`Напишите ${service.worker} через форму заказа`);
    return;
  }
  
  // Заполняем данные исполнителя
  const workerName = document.getElementById('contactWorkerName');
  const workerRole = document.getElementById('contactWorkerRole');
  if (workerName) workerName.textContent = service.worker;
  if (workerRole) workerRole.textContent = service.workerRole;
  
  // Telegram блок
  const telegramBlock = document.getElementById('contactTelegram');
  const telegramLink = telegramBlock?.querySelector('a');
  const telegramValue = document.getElementById('telegramValue');
  
  if (service.telegram && telegramBlock && telegramLink && telegramValue) {
    telegramValue.textContent = service.telegram;
    const tgUsername = service.telegram.replace('@', '');
    telegramLink.href = `https://t.me/${tgUsername}`;
    telegramBlock.style.display = 'block';
  } else if (telegramBlock) {
    telegramBlock.style.display = 'none';
  }
  
  // MAX блок
  const maxBlock = document.getElementById('contactMax');
  const maxLink = maxBlock?.querySelector('a');
  const maxValue = document.getElementById('maxValue');
  
  if (service.max && maxBlock && maxLink && maxValue) {
    maxValue.textContent = service.max;
    const maxPhone = service.max.replace(/\D/g, '');
    maxLink.href = `https://max.ru/${maxPhone}`;
    maxBlock.style.display = 'block';
  } else if (maxBlock) {
    maxBlock.style.display = 'none';
  }
  
  // Открываем модальное окно
  openModal('contactModal');
}

function closeContactModal() {
  closeModal('contactModal');
}

// ===== ВЫХОД =====

function logout() {
  localStorage.clear();
  window.location.href = "/auto.html";
}