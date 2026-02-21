// Проверка авторизации при загрузке страницы
document.addEventListener("DOMContentLoaded", function () {
  checkAuth();
  initModals();
  initForms();
});

// Проверка токена и авторизации
async function checkAuth() {
  const token = localStorage.getItem("token");
  const currentPath = window.location.pathname;

  // Если на странице входа и есть токен - перенаправляем
  if (token && (currentPath.includes("auto.html") || currentPath === "/")) {
    try {
      const response = await fetch("/api/validate-token", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
        },
      });

      const data = await response.json();

      if (data.valid) {
        if (data.role === "admin") {
          window.location.href = "/admin.html";
        } else if (data.role === "worker") {
          window.location.href = "/worker.html";
        }
      }
    } catch (error) {
      console.error("Ошибка проверки токена:", error);
    }
  }

  // Защита страниц admin.html и worker.html
  if (
    currentPath.includes("admin.html") ||
    currentPath.includes("worker.html")
  ) {
    if (!token) {
      window.location.href = "/auto.html";
      return;
    }

    try {
      const response = await fetch("/api/validate-token", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
        },
      });

      const data = await response.json();

      if (!data.valid) {
        localStorage.removeItem("token");
        window.location.href = "/auto.html";
        return;
      }

      // Проверка роли
      if (currentPath.includes("admin.html") && data.role !== "admin") {
        alert("❌ Доступ запрещен. Требуется роль администратора.");
        window.location.href = "/auto.html";
        return;
      }

      if (currentPath.includes("worker.html") && data.role !== "worker") {
        alert("❌ Доступ запрещен. Требуется роль работника.");
        window.location.href = "/auto.html";
        return;
      }

      // Отображение имени пользователя
      if (data.name) {
        updateUserName(data.name);
      }
    } catch (error) {
      console.error("Ошибка проверки авторизации:", error);
      localStorage.removeItem("token");
      window.location.href = "/auto.html";
    }
  }
}

// Обновление имени пользователя на странице
function updateUserName(name) {
  // Для worker.html
  const workerNameElement = document.querySelector(".text-2xl.font-semibold");
  if (workerNameElement) {
    workerNameElement.textContent = name;
  }

  // Альтернативный поиск для worker.html
  const greetingElement = document.querySelector("h2");
  if (greetingElement && greetingElement.textContent.includes("Добрый день")) {
    // Имя уже в тексте приветствия
  }
}

// Обработчик входа с JWT
async function handleLogin(event) {
  event.preventDefault();

  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const remember = document.getElementById("remember").checked;

  const loginBtn = event.target.querySelector(".login-btn");
  const originalText = loginBtn.innerHTML;
  loginBtn.innerHTML =
    '<span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">progress_activity</span> Вход...';
  loginBtn.disabled = true;

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: email,
        password: password,
      }),
    });

    const data = await response.json();

    if (data.success) {
      // Сохраняем токен
      if (remember) {
        localStorage.setItem("token", data.token);
      } else {
        sessionStorage.setItem("token", data.token);
      }
      localStorage.setItem("userRole", data.role);

      // Показываем успех
      loginBtn.innerHTML =
        '<span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">check</span> Успешно!';
      loginBtn.style.background = "#10b981";

      setTimeout(() => {
        // Перенаправление в зависимости от роли
        if (data.role === "admin") {
          window.location.href = "/admin.html";
        } else if (data.role === "worker") {
          window.location.href = "/worker.html";
        } else {
          alert("❌ Неизвестная роль пользователя");
          loginBtn.innerHTML = originalText;
          loginBtn.disabled = false;
          loginBtn.style.background = "";
        }
      }, 500);
    } else {
      alert("❌ " + data.message);
      loginBtn.innerHTML = originalText;
      loginBtn.disabled = false;
    }
  } catch (error) {
    console.error("Ошибка входа:", error);
    alert("❌ Ошибка подключения к серверу. Проверьте, запущен ли сервер.");
    loginBtn.innerHTML = originalText;
    loginBtn.disabled = false;
  }
}

// Показ/скрытие пароля
function togglePassword() {
  const passwordInput = document.getElementById("password");
  const toggleIcon = document.getElementById("toggleIcon");

  if (passwordInput.type === "password") {
    passwordInput.type = "text";
    toggleIcon.textContent = "visibility_off";
  } else {
    passwordInput.type = "password";
    toggleIcon.textContent = "visibility";
  }
}

// Выход из системы
function logout() {
  localStorage.removeItem("token");
  sessionStorage.removeItem("token");
  localStorage.removeItem("userRole");
  window.location.href = "/auto.html";
}

// Инициализация модальных окон
function initModals() {
  // Кнопки открытия модальных окон
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

  // Кнопки закрытия модальных окон
  document.querySelectorAll(".modal-close").forEach((btn) => {
    btn.addEventListener("click", function () {
      const modalId = this.getAttribute("data-modal");
      closeModal(modalId);
    });
  });

  // Закрытие по клику вне модального окна
  document.querySelectorAll(".modal").forEach((modal) => {
    modal.addEventListener("click", function (e) {
      if (e.target === this) {
        closeModal(this.id);
      }
    });
  });

  // Закрытие по Escape
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      const activeModal = document.querySelector(".modal.active");
      if (activeModal) {
        closeModal(activeModal.id);
      }
    }
  });
}

// Открытие модального окна
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add("active");
    document.body.style.overflow = "hidden";
  }
}

// Закрытие модального окна
function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove("active");
    document.body.style.overflow = "";
  }
}

// Закрытие всех модальных окон
function closeAllModals() {
  document.querySelectorAll(".modal").forEach((modal) => {
    modal.classList.remove("active");
  });
  document.body.style.overflow = "";
}

// Инициализация форм
function initForms() {
  // Форма поддержки
  const supportForm = document.querySelector(".support-form");
  if (supportForm) {
    supportForm.addEventListener("submit", function (e) {
      e.preventDefault();
      alert("✅ Сообщение отправлено! Мы ответим вам в ближайшее время.");
      closeAllModals();
      supportForm.reset();
    });
  }

  // Форма восстановления пароля
  const forgotForm = document.querySelector(".forgot-form");
  if (forgotForm) {
    forgotForm.addEventListener("submit", function (e) {
      e.preventDefault();
      alert("✅ Инструкция по восстановлению пароля отправлена на вашу почту!");
      closeAllModals();
      forgotForm.reset();
    });
  }
}
