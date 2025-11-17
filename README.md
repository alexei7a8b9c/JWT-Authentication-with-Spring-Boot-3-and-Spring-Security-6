The advantages of this approach:

Step-by-step testing - each request can be run separately

Automatic saving of tokens into variables

Testing of all scenarios - success and failure cases

Response validation using JavaScript assertions

Test process logging

Using test data from migrations and creating new ones

JWT Authentication with Spring Boot 3 and Spring Security 6

This project demonstrates the implementation of JWT authentication using Spring Boot 3, Spring Security 6, PostgreSQL, and Flyway. Technologies

Java 21

Spring Boot 3.2.0

Spring Security 6

PostgreSQL - database

Flyway - database migrations

JWT - JSON Web Tokens for authentication

Maven - dependency management

SpringDoc OpenAPI - API documentation

Functionality

New user registration

WT authentication and authorization

Role model (USER/ADMIN)

Secure endpoints

Data validation

Swagger documentation

Automated database migrations
Quick Start
1. Starting the Database
   bash

docker-compose up -d

2. Starting the Application
   bash

mvn spring-boot:run

3. API Documentation

Open in a browser: http://localhost:8080/swagger-ui/index.html
API Endpoints
Authentication
Method Endpoint Description Access
POST /auth/sign-up User registration Public
POST /auth/sign-in User authorization Public
Example Endpoints
Method Endpoint Description Access
GET /example Example of a secure endpoint Authenticated
GET /example/admin Example of an admin endpoint ROLE_ADMIN
GET /example/get-admin Get ADMIN Authenticated privileges
Test Users

After running migrations, test users are created:
Administrators:

admin / admin123 (initial) Admin)

Regular users:

user1 / user123

user2 / user123

testuser / user123

Testing
Method 1: Swagger UI

Open http://localhost:8080/swagger-ui/index.html

Use the interface to test the API

Method 2: HTTP Client (IntelliJ IDEA)

Run tests from the files:

http-requests.http - basic tests

http-admin-tests.http - admin tests

Configuration
Basic settings (application-dev.yml)
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

Database Migrations

V1__Create_users_table.sql - Create a user table

V2__Insert_test_data.sql - Test data

Security
JWT Token

The token contains:

User ID

Email

Role

Creation time and expiration

Endpoint Security

permitAll() - Public access

authenticated() - For authorized users

hasRole('ADMIN') - for administrators only
