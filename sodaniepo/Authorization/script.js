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
    document.querySelectorAll('.form-error').forEach(el => el.classList.remove('active'));
  }
}

function contactWorker() {
  if (!currentService) return;
  
  if (!currentService.telegram && !currentService.max) {
    alert(`Напишите ${currentService.worker} через форму заказа`);
    return;
  }
  
  const workerName = document.getElementById('contactWorkerName');
  const workerRole = document.getElementById('contactWorkerRole');
  if (workerName) workerName.textContent = currentService.worker;
  if (workerRole) workerRole.textContent = currentService.workerRole;
  
  const telegramBlock = document.getElementById('contactTelegram');
  const telegramLink = telegramBlock?.querySelector('a');
  const telegramValue = document.getElementById('telegramValue');
  
  if (currentService.telegram && telegramBlock && telegramLink && telegramValue) {
    telegramValue.textContent = currentService.telegram;
    const tgUsername = currentService.telegram.replace('@', '');
    telegramLink.href = `https://t.me/${tgUsername}`;
    telegramBlock.style.display = 'flex';
  } else if (telegramBlock) {
    telegramBlock.style.display = 'none';
  }
  
  const maxBlock = document.getElementById('contactMax');
  const maxLink = maxBlock?.querySelector('a');
  const maxValue = document.getElementById('maxValue');
  
  if (currentService.max && maxBlock && maxLink && maxValue) {
    maxValue.textContent = currentService.max;
    const maxPhone = currentService.max.replace(/\D/g, '');
    maxLink.href = `https://max.ru/${maxPhone}`;
    maxBlock.style.display = 'flex';
  } else if (maxBlock) {
    maxBlock.style.display = 'none';
  }
  
  openModal('contactModal');
}

function closeContactModal() {
  closeModal('contactModal');
}

function logout() {
  localStorage.clear();
  window.location.href = "/auto.html";
}

function openLoginModal() { openModal('loginModal'); }
function closeLoginModal() { closeModal('loginModal'); }
function openRegisterModal() { openModal('registerModal'); }
function closeRegisterModal() { closeModal('registerModal'); }
function closeServiceModal() { closeModal('serviceModal'); }

function switchToRegister() {
  closeLoginModal();
  setTimeout(() => openRegisterModal(), 200);
}

function switchToLogin() {
  closeRegisterModal();
  setTimeout(() => openLoginModal(), 200);
}

function selectRole(role, element) {
  document.querySelectorAll('.role-option').forEach(el => el.classList.remove('selected'));
  element.classList.add('selected');
  document.querySelector(`input[name="userRole"][value="${role}"]`).checked = true;
  
  const workerFields = document.getElementById('workerFields');
  if (role === 'worker') {
    workerFields.classList.add('active');
  } else {
    workerFields.classList.remove('active');
  }
}

async function handleRegister(event) {
  event.preventDefault();
  
  const email = document.getElementById('registerEmail').value.trim();
  const name = document.getElementById('registerName').value.trim();
  const password = document.getElementById('registerPassword').value;
  const confirmPassword = document.getElementById('registerConfirmPassword').value;
  const role = document.querySelector('input[name="userRole"]:checked').value;
  const submitBtn = document.getElementById('registerBtn');
  const originalText = submitBtn.textContent;

  document.querySelectorAll('.form-error').forEach(el => el.classList.remove('active'));

  let hasError = false;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    document.getElementById('emailError').classList.add('active');
    hasError = true;
  }
  if (password.length < 6) {
    document.getElementById('passwordError').classList.add('active');
    hasError = true;
  }
  if (password !== confirmPassword) {
    document.getElementById('confirmError').classList.add('active');
    hasError = true;
  }
  if (hasError) return;

  const registerData = { email, password, name, role };

  if (role === 'worker') {
    registerData.worker_profile = {
      specialty: document.getElementById('workerSpecialty').value,
      experience_years: parseInt(document.getElementById('workerExperience').value) || 0,
      phone: document.getElementById('workerPhone').value,
      telegram: document.getElementById('workerTelegram').value,
      description: document.getElementById('workerDescription').value
    };
  }

  submitBtn.textContent = '⏳ Регистрация...';
  submitBtn.disabled = true;

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(registerData)
    });
    
    const data = await response.json();

    if (response.ok) {
      alert(`✅ ${data.message || 'Регистрация успешна!'}\nТеперь вы можете войти.`);
      closeRegisterModal();
      document.getElementById('registerForm').reset();
      selectRole('customer', document.querySelector('.role-option:first-child'));
      switchToLogin();
      document.getElementById('loginEmail').value = email;
    } else {
      alert(`❌ ${data.error || 'Ошибка регистрации'}`);
    }
  } catch (error) {
    console.error('Ошибка регистрации:', error);
    alert('❌ Ошибка подключения к серверу');
  } finally {
    submitBtn.textContent = originalText;
    submitBtn.disabled = false;
  }
}

window.onclick = function(event) {
  ['serviceModal', 'loginModal', 'registerModal', 'contactModal'].forEach(id => {
    const modal = document.getElementById(id);
    if (modal && event.target === modal) closeModal(id);
  });
};

document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    ['serviceModal', 'loginModal', 'registerModal', 'contactModal'].forEach(id => {
      const modal = document.getElementById(id);
      if (modal && modal.classList.contains('active')) closeModal(id);
    });
  }
});