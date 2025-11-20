// static/js/safe-tokens.js

class SecureTokenManager {
    constructor() {
        this.accessToken = null;
        this.refreshToken = null;
        this.csrfToken = null;
        this.isInitialized = false;

        this.init();
    }

    init() {
        this.cleanupInsecureStorage();
        this.loadCsrfToken();
        this.isInitialized = true;
        console.log('SecureTokenManager initialized');
    }

    // Очистка небезопасного хранения
    cleanupInsecureStorage() {
        // Удаляем токены из localStorage и sessionStorage
        const storageKeys = ['accessToken', 'refreshToken', 'jwtToken', 'token'];

        storageKeys.forEach(key => {
            localStorage.removeItem(key);
            sessionStorage.removeItem(key);
        });

        // Очищаем куки, которые могут содержать токены (кроме наших защищенных)
        this.clearInsecureCookies();
    }

    clearInsecureCookies() {
        const insecureCookies = ['token', 'jwt', 'auth_token'];
        insecureCookies.forEach(cookieName => {
            document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
        });
    }

    // Загрузка CSRF токена из куки
    loadCsrfToken() {
        this.csrfToken = this.getCookie('XSRF-TOKEN');
    }

    // Безопасное получение куки
    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) {
            return parts.pop().split(';').shift();
        }
        return null;
    }

    // Проверка аутентификации
    isAuthenticated() {
        // Проверяем наличие CSRF токена как индикатора аутентификации
        return this.csrfToken !== null;
    }

    // Безопасный HTTP запрос
    async makeSecureRequest(url, options = {}) {
        if (!this.isInitialized) {
            throw new Error('TokenManager not initialized');
        }

        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        // Добавляем CSRF токен для модифицирующих запросов
        if (this.csrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(options.method)) {
            headers['X-XSRF-TOKEN'] = this.csrfToken;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers,
                credentials: 'include' // Важно для HTTP-only cookies
            });

            // Обработка 401 Unauthorized
            if (response.status === 401) {
                console.log('Token expired, attempting refresh...');
                const refreshed = await this.refreshTokens();
                if (refreshed) {
                    // Повторяем оригинальный запрос
                    return this.makeSecureRequest(url, options);
                } else {
                    this.handleAuthFailure();
                    throw new Error('Authentication failed');
                }
            }

            // Обработка 403 Forbidden
            if (response.status === 403) {
                this.handleForbidden();
                throw new Error('Access denied');
            }

            return response;

        } catch (error) {
            console.error('Secure request failed:', error);
            throw error;
        }
    }

    // Обновление токенов
    async refreshTokens() {
        try {
            const response = await this.makeSecureRequest('/auth/web-refresh', {
                method: 'POST'
            });

            if (response.ok) {
                const data = await response.json();
                console.log('Tokens refreshed successfully');
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
        }

        return false;
    }

    // Обработка ошибки аутентификации
    handleAuthFailure() {
        this.logout();

        // Показываем сообщение пользователю
        this.showMessage('Сессия истекла. Пожалуйста, войдите снова.', 'error');

        // Перенаправляем на страницу логина
        setTimeout(() => {
            window.location.href = '/login?tokenExpired=true';
        }, 2000);
    }

    // Обработка запрета доступа
    handleForbidden() {
        this.showMessage('Доступ запрещен', 'error');
    }

    // Безопасный logout
    async logout() {
        try {
            await this.makeSecureRequest('/auth/web-logout', {
                method: 'POST'
            });
        } catch (error) {
            console.error('Logout request failed:', error);
        } finally {
            this.clearLocalState();
            window.location.href = '/?logout=true';
        }
    }

    // Простой logout без запроса к серверу
    simpleLogout() {
        this.clearTokenCookies();
        this.clearLocalState();
        window.location.href = '/?logout=true';
    }

    // Очистка токен куки
    clearTokenCookies() {
        // Очищаем access token
        document.cookie = "accessToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";

        // Очищаем refresh token
        document.cookie = "refreshToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";

        // Очищаем CSRF token
        document.cookie = "XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    }

    // Очистка локального состояния
    clearLocalState() {
        this.accessToken = null;
        this.refreshToken = null;
        this.csrfToken = null;
        this.cleanupInsecureStorage();
    }

    // Показать сообщение пользователю
    showMessage(message, type = 'info') {
        // Создаем или находим контейнер для сообщений
        let messageContainer = document.getElementById('secure-messages');
        if (!messageContainer) {
            messageContainer = document.createElement('div');
            messageContainer.id = 'secure-messages';
            messageContainer.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                max-width: 400px;
            `;
            document.body.appendChild(messageContainer);
        }

        // Создаем сообщение
        const messageElement = document.createElement('div');
        messageElement.style.cssText = `
            padding: 12px 16px;
            margin-bottom: 10px;
            border-radius: 4px;
            color: white;
            font-family: Arial, sans-serif;
            font-size: 14px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            animation: slideIn 0.3s ease-out;
        `;

        // Стили в зависимости от типа
        const styles = {
            error: 'background-color: #dc3545;',
            success: 'background-color: #28a745;',
            info: 'background-color: #17a2b8;',
            warning: 'background-color: #ffc107; color: #212529;'
        };

        messageElement.style.cssText += styles[type] || styles.info;

        messageElement.textContent = message;
        messageContainer.appendChild(messageElement);

        // Автоматическое удаление через 5 секунд
        setTimeout(() => {
            if (messageElement.parentNode) {
                messageElement.parentNode.removeChild(messageElement);
            }
        }, 5000);
    }

    // Защита от XSS - санитизация ввода
    sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    // Проверка безопасности URL
    isSafeUrl(url) {
        try {
            const parsedUrl = new URL(url, window.location.origin);
            return parsedUrl.origin === window.location.origin;
        } catch {
            return false;
        }
    }
}

// CSS для анимаций
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
`;
document.head.appendChild(style);

// Глобальная инициализация
document.addEventListener('DOMContentLoaded', function() {
    window.tokenManager = new SecureTokenManager();

    // Защита от вставки токенов в формы
    document.addEventListener('submit', function(e) {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            // Удаляем любые скрытые поля с токенами
            const tokenInputs = form.querySelectorAll('input[type="hidden"][name*="token"], input[type="hidden"][name*="Token"]');
            tokenInputs.forEach(input => input.remove());
        });
    });

    // Глобальная функция logout для использования в кнопках
    window.logout = function() {
        if (window.tokenManager) {
            window.tokenManager.simpleLogout();
        } else {
            // Fallback если tokenManager не инициализирован
            document.cookie = "accessToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            document.cookie = "refreshToken=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            document.cookie = "XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            window.location.href = '/?logout=true';
        }
    };
});

// Защита от кражи токенов через console.log
if (typeof console !== 'undefined') {
    const originalLog = console.log;
    console.log = function(...args) {
        // Фильтруем логи, содержащие токены
        const filteredArgs = args.map(arg => {
            if (typeof arg === 'string' && (arg.includes('Bearer ') || arg.length > 100)) {
                return '[SECURE TOKEN HIDDEN]';
            }
            return arg;
        });
        originalLog.apply(console, filteredArgs);
    };
}