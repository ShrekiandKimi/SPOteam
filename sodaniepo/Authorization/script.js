// Конфигурация
const API_URL = "";
const ACCESS_TOKEN_KEY = "accessToken";
const REFRESH_TOKEN_KEY = "refreshToken";
const TOKEN_EXPIRY_KEY = "tokenExpiry";

// Проверка авторизации при загрузке
document.addEventListener("DOMContentLoaded", function () {
  checkAuth();
  initModals();
  initForms();
  startTokenRefreshCheck();
});

// Проверка токена
async function checkAuth() {
  const token = localStorage.getItem(ACCESS_TOKEN_KEY);
  const currentPath = window.location.pathname;

  if (!token) {
    if (!currentPath.includes("auto.html") && currentPath !== "/") {
      window.location.href = "/auto.html";
    }
    return;
  }

  try {
    const response = await fetch(`${API_URL}/api/validate-token`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    const data = await response.json();

    if (data.valid) {
      if (currentPath.includes("auto.html") || currentPath === "/") {
        if (data.role === "admin") {
          window.location.href = "/admin.html";
        } else if (data.role === "worker") {
          window.location.href = "/worker.html";
        }
      } else {
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
        if (data.name) updateUserName(data.name);
      }
    } else {
      const refreshed = await refreshAccessToken();
      if (!refreshed) logout(false);
    }
  } catch (error) {
    console.error("Ошибка проверки токена:", error);
    const refreshed = await refreshAccessToken();
    if (!refreshed && !currentPath.includes("auto.html")) logout(false);
  }
}

// Обновление access токена
async function refreshAccessToken() {
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
  if (!refreshToken) return false;

  try {
    const response = await fetch(`${API_URL}/api/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    const data = await response.json();
    if (data.success) {
      localStorage.setItem(ACCESS_TOKEN_KEY, data.accessToken);
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refreshToken);
      localStorage.setItem(
        TOKEN_EXPIRY_KEY,
        Date.now() + data.expiresIn * 1000,
      );
      return true;
    }
  } catch (error) {
    console.error("Ошибка обновления токена:", error);
  }
  return false;
}

// Периодическая проверка истечения токена
function startTokenRefreshCheck() {
  setInterval(async () => {
    const expiry = localStorage.getItem(TOKEN_EXPIRY_KEY);
    if (expiry) {
      const timeLeft = parseInt(expiry) - Date.now();
      if (timeLeft < 5 * 60 * 1000 && timeLeft > 0) {
        console.log("🔄 Обновление токена...");
        await refreshAccessToken();
      }
    }
  }, 60 * 1000);
}

// Вход в систему
async function handleLogin(event) {
  event.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const loginBtn = document.querySelector(".login-btn");
  const originalText = loginBtn.innerHTML;

  loginBtn.innerHTML =
    '<span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">progress_activity</span> Вход...';
  loginBtn.disabled = true;

  try {
    const response = await fetch(`${API_URL}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await response.json();

    if (data.success) {
      localStorage.setItem(ACCESS_TOKEN_KEY, data.accessToken);
      localStorage.setItem(REFRESH_TOKEN_KEY, data.refreshToken);
      localStorage.setItem(
        TOKEN_EXPIRY_KEY,
        Date.now() + data.expiresIn * 1000,
      );

      loginBtn.innerHTML =
        '<span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">check</span> Успешно!';
      loginBtn.style.background = "#10b981";

      setTimeout(() => {
        window.location.href =
          data.role === "admin" ? "/admin.html" : "/worker.html";
      }, 500);
    } else {
      alert("❌ " + data.message);
      loginBtn.innerHTML = originalText;
      loginBtn.disabled = false;
      loginBtn.style.background = "";
    }
  } catch (error) {
    console.error("Ошибка входа:", error);
    alert("❌ Ошибка подключения к серверу");
    loginBtn.innerHTML = originalText;
    loginBtn.disabled = false;
  }
}

// Выход из системы
async function logout(notify = true) {
  const accessToken = localStorage.getItem(ACCESS_TOKEN_KEY);
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);

  if (accessToken || refreshToken) {
    try {
      await fetch(`${API_URL}/api/logout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accessToken, refreshToken }),
      });
    } catch (error) {
      console.error("Ошибка при logout:", error);
    }
  }

  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(TOKEN_EXPIRY_KEY);

  if (notify) alert("✅ Вы вышли из системы");
  window.location.href = "/auto.html";
}

// Обновление имени пользователя
function updateUserName(name) {
  const elements = document.querySelectorAll(
    ".text-2xl.font-semibold, h2, .user-name",
  );
  elements.forEach((el) => {
    if (el.textContent.includes("Добрый день") || el.tagName === "H2") {
      el.textContent = `Добрый день, ${name.split(" ")[0]}!`;
    } else {
      el.textContent = name;
    }
  });
}

// Инициализация модальных окон
function initModals() {
  document.querySelectorAll("[data-modal]").forEach((btn) => {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      openModal(this.getAttribute("data-modal"));
    });
  });
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
}

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

// Инициализация форм
function initForms() {
  const loginForm = document.getElementById("loginForm");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);

  const supportForm = document.querySelector(".support-form");
  if (supportForm) {
    supportForm.addEventListener("submit", function (e) {
      e.preventDefault();
      alert("✅ Сообщение отправлено! Мы ответим вам в ближайшее время.");
      closeAllModals();
      supportForm.reset();
    });
  }

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
