document.addEventListener("DOMContentLoaded", function () {
  // === Модальные окна ===
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
  function closeAllModals() {
    document.querySelectorAll(".modal").forEach((modal) => {
      modal.classList.remove("active");
    });
    document.body.style.overflow = "";
  }

  // Кнопки модальных окон
  const supportBtn = document.getElementById("btn-support");
  if (supportBtn) {
    supportBtn.addEventListener("click", function (e) {
      e.preventDefault();
      openModal("modal-support");
    });
  }
  const adminBtn = document.getElementById("btn-admin");
  if (adminBtn) {
    adminBtn.addEventListener("click", function (e) {
      e.preventDefault();
      openModal("modal-admin");
    });
  }
  const forgotBtn = document.getElementById("btn-forgot");
  if (forgotBtn) {
    forgotBtn.addEventListener("click", function (e) {
      e.preventDefault();
      openModal("modal-forgot");
    });
  }

  document.querySelectorAll(".modal-close").forEach((btn) => {
    btn.addEventListener("click", function () {
      closeModal(this.getAttribute("data-modal"));
    });
  });
  document.querySelectorAll(".modal").forEach((modal) => {
    modal.addEventListener("click", function (e) {
      if (e.target === this) closeModal(this.id);
    });
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      const activeModal = document.querySelector(".modal.active");
      if (activeModal) closeModal(activeModal.id);
    }
  });

  // Формы
  const supportForm = document.querySelector(".support-form");
  if (supportForm) {
    supportForm.addEventListener("submit", function (e) {
      e.preventDefault();
      alert("✅ Сообщение отправлено!");
      closeAllModals();
      supportForm.reset();
    });
  }
  const forgotForm = document.querySelector(".forgot-form");
  if (forgotForm) {
    forgotForm.addEventListener("submit", function (e) {
      e.preventDefault();
      alert("✅ Инструкция отправлена!");
      closeAllModals();
      forgotForm.reset();
    });
  }

  // 🔐 ВХОД ЧЕРЕЗ API
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async function (e) {
      e.preventDefault();
      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;
      const btn = this.querySelector(".login-btn");
      const originalText = btn.innerHTML;

      btn.innerHTML = "⏳ Вход...";
      btn.disabled = true;

      try {
        const response = await fetch("/api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password }),
        });
        const data = await response.json();

        if (data.success) {
          localStorage.setItem("accessToken", data.accessToken);
          localStorage.setItem("userRole", data.role);

          if (data.role === "admin") {
            window.location.href = "/admin.html";
          } else if (data.role === "worker") {
            window.location.href = "/worker.html";
          }
        } else {
          alert("❌ " + data.message);
          btn.innerHTML = originalText;
          btn.disabled = false;
        }
      } catch (error) {
        console.error("Ошибка входа:", error);
        alert("❌ Ошибка подключения к серверу");
        btn.innerHTML = originalText;
        btn.disabled = false;
      }
    });
  }

  // Показать/скрыть пароль
  const toggleBtn = document.querySelector(".password-toggle");
  const pwdInput = document.getElementById("password");
  const toggleIcon = document.getElementById("toggleIcon");
  if (toggleBtn && pwdInput) {
    toggleBtn.addEventListener("click", function () {
      const isPwd = pwdInput.type === "password";
      pwdInput.type = isPwd ? "text" : "password";
      if (toggleIcon)
        toggleIcon.textContent = isPwd ? "visibility_off" : "visibility";
    });
  }

  // Проверка авторизации
  async function checkAuth() {
    const token = localStorage.getItem("accessToken");
    const path = window.location.pathname;

    if (!token && !path.includes("auto.html")) {
      window.location.href = "/auto.html";
      return;
    }

    if (token && path.includes("auto.html")) {
      try {
        const res = await fetch("/api/validate-token", {
          method: "POST",
          headers: { Authorization: "Bearer " + token },
        });
        const data = await res.json();
        if (data.valid) {
          window.location.href =
            data.role === "admin" ? "/admin.html" : "/worker.html";
        } else {
          localStorage.clear();
        }
      } catch (e) {}
    }
  }
  checkAuth();
});

// Выход
function logout() {
  localStorage.clear();
  window.location.href = "/auto.html";
}
