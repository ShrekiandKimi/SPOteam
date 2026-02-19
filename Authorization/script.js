document.addEventListener('DOMContentLoaded', function() {
  
  function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('active');
      document.body.style.overflow = 'hidden';
    }
  }
  
  function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
      document.body.style.overflow = '';
    }
  }
  
  function closeAllModals() {
    document.querySelectorAll('.modal').forEach(modal => {
      modal.classList.remove('active');
    });
    document.body.style.overflow = '';
  }
  
  const supportBtn = document.getElementById('btn-support');
  if (supportBtn) {
    supportBtn.addEventListener('click', function(e) {
      e.preventDefault();
      openModal('modal-support');
    });
  }
  
  const adminBtn = document.getElementById('btn-admin');
  if (adminBtn) {
    adminBtn.addEventListener('click', function(e) {
      e.preventDefault();
      openModal('modal-admin');
    });
  }
  
  const forgotBtn = document.getElementById('btn-forgot');
  if (forgotBtn) {
    forgotBtn.addEventListener('click', function(e) {
      e.preventDefault();
      openModal('modal-forgot');
    });
  }
  
  document.querySelectorAll('.modal-close').forEach(btn => {
    btn.addEventListener('click', function() {
      const modalId = this.getAttribute('data-modal');
      closeModal(modalId);
    });
  });
  
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', function(e) {
      if (e.target === this) {
        closeModal(this.id);
      }
    });
  });
  
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      const activeModal = document.querySelector('.modal.active');
      if (activeModal) {
        closeModal(activeModal.id);
      }
    }
  });
  
  const supportForm = document.querySelector('.support-form');
  if (supportForm) {
    supportForm.addEventListener('submit', function(e) {
      e.preventDefault();
      alert('✅ Сообщение отправлено! Мы ответим вам в ближайшее время.');
      closeAllModals();
      supportForm.reset();
    });
  }
  
  const forgotForm = document.querySelector('.forgot-form');
  if (forgotForm) {
    forgotForm.addEventListener('submit', function(e) {
      e.preventDefault();
      alert('✅ Инструкция по восстановлению пароля отправлена на вашу почту!');
      closeAllModals();
      forgotForm.reset();
    });
  }
  
  const loginForm = document.querySelector('form');
  if (loginForm) {
    loginForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      
      if (email && password) {
        alert('✅ Вход выполнен!\nEmail: ' + email);
      } else {
        alert('❌ Введите email и пароль');
      }
    });
  }
  
  const togglePasswordBtn = document.querySelector('button[type="button"]');
  const passwordInput = document.getElementById('password');
  
  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener('click', function() {
      const type = passwordInput.type === 'password' ? 'text' : 'password';
      passwordInput.type = type;
      const icon = this.querySelector('.material-symbols-outlined');
      if (icon) {
        icon.textContent = type === 'password' ? 'visibility' : 'visibility_off';
      }
    });
  }
  
});