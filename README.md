Преимущества этого подхода:

Пошаговое тестирование - каждый запрос можно запустить отдельно

Автоматическое сохранение токенов в переменные

Проверка всех сценариев - успешные и ошибочные кейсы

Валидация ответов с помощью JavaScript assertions

Логирование процесса тестирования

Использование тестовых данных из миграции и создание новых

JWT Authentication with Spring Boot 3 and Spring Security 6

Проект демонстрирует реализацию JWT-аутентификации с использованием Spring Boot 3, Spring Security 6, PostgreSQL и Flyway.
Технологии

    Java 21

    Spring Boot 3.2.0

    Spring Security 6

    PostgreSQL - база данных

    Flyway - миграции базы данных

    JWT - JSON Web Tokens для аутентификации

    Maven - управление зависимостями

    SpringDoc OpenAPI - документация API

 Функциональность

Регистрация новых пользователей

WT аутентификация и авторизация

Ролевая модель (USER/ADMIN)

Защищенные эндпоинты

Валидация данных

Swagger документация

Автоматические миграции базы данных

Быстрый старт
1. Запуск базы данных
   bash

docker-compose up -d

2. Запуск приложения
   bash

mvn spring-boot:run

3. Документация API

Откройте в браузере: http://localhost:8080/swagger-ui/index.html
API Endpoints
Аутентификация
Метод	Endpoint	Описание	Доступ
POST	/auth/sign-up	Регистрация пользователя	Public
POST	/auth/sign-in	Авторизация пользователя	Public
Примеры эндпоинтов
Метод	Endpoint	Описание	Доступ
GET	/example	Пример защищенного эндпоинта	Authenticated
GET	/example/admin	Пример админского эндпоинта	ROLE_ADMIN
GET	/example/get-admin	Получить права ADMIN	Authenticated
Тестовые пользователи

После запуска миграций создаются тестовые пользователи:
Администраторы:

    admin / admin123 (изначальный админ)

Обычные пользователи:

    user1 / user123

    user2 / user123

    testuser / user123

Тестирование
Способ 1: Swagger UI

    Откройте http://localhost:8080/swagger-ui/index.html

    Используйте интерфейс для тестирования API

Способ 2: HTTP Client (IntelliJ IDEA)

Запустите тесты из файлов:

    http-requests.http - базовые тесты

    http-admin-tests.http - тесты администраторов


Конфигурация
Основные настройки (application-dev.yml)
yaml

server:
port: 8080

spring:
datasource:
url: jdbc:postgresql://localhost:5432/jwt_auth
username: pos
password: 1234567

flyway:
enabled: true
locations: classpath:db/migration

token:
signing:
key: "your-secret-key-here"

Docker Compose
yaml

services:
postgres:
image: postgres:15
environment:
POSTGRES_DB: jwt_auth
POSTGRES_USER: pos
POSTGRES_PASSWORD: 1234567
ports:
- "5432:5432"


Миграции базы данных

    V1__Create_users_table.sql - создание таблицы пользователей

    V2__Insert_test_data.sql - тестовые данные

Безопасность
JWT Токен

Токен содержит:

    Идентификатор пользователя

    Email

    Роль

    Время создания и expiration

Защита эндпоинтов

    permitAll() - публичный доступ

    authenticated() - для авторизованных пользователей

    hasRole('ADMIN') - только для администраторов

