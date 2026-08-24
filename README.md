# Spring Cloud API Gateway (Production-Ready)

Centralized reactive API Gateway built on **Spring Cloud Gateway** and **Spring Security WebFlux (OAuth2 Resource Server)** for microservice architectures.

---

## 🌟 Architectural Overview

```
                          ┌────────────────────────┐
                          │   Client (Web/Mobile)  │
                          └───────────┬────────────┘
                                      │ Bearer Token / Cookie
                                      ▼
             ┌──────────────────────────────────────────────────┐
             │               SPRING CLOUD GATEWAY               │
             │                                                  │
             │ 1. CORS Preflight & Filter                       │
             │ 2. Public Path Check (permitAll)                 │
             │ 3. Extract JWT (Header or HttpOnly Cookie)       │
             │ 4. RS256 Signature & Expiry Verification        │
             │ 5. AuthHeaderRelayFilter:                        │
             │    - Overwrite/Strip Spoofed Headers             │
             │    - Inject X-User-Id, X-User-Roles, etc.        │
             └───────────────────────┬──────────────────────────┘
                                     │ Trusted Headers + Authorization
                   ┌─────────────────┴─────────────────┐
                   ▼                                   ▼
        ┌─────────────────────┐             ┌─────────────────────┐
        │  Auth Service :8080 │             │ Workflow / Service  │
        └─────────────────────┘             └─────────────────────┘
```

---

## 🚀 Key Features

1. **Centralized JWT Validation**:
   - Decodes and validates **RS256 asymmetric JWTs** at the gateway boundary.
   - Downstream services don't need redundant JWT parsing logic.
2. **Dynamic & Fallback Public Key Resolution**:
   - Fetches public key dynamically from auth server endpoint (`/auth/public-key`) or JWKS URI (`/.well-known/jwks.json`).
   - Automatically falls back to local PEM key file (`keys/public.pem`) if the auth server is unreachable during startup.
3. **Dual Token Source Extraction**:
   - Supports standard `Authorization: Bearer <token>` header.
   - Supports HTTP-only cookie (`accessToken`) for browser SPA/SSR applications.
4. **Context Propagation (`AuthHeaderRelayFilter`)**:
   - Injects clean downstream headers: `X-User-Id`, `X-User-Roles`, `X-User-Email`.
   - Prevents external header spoofing by overwriting incoming `X-User-*` headers.
5. **Clean JSON Error Responses**:
   - Custom entry point returning standard `401 Unauthorized` and `403 Forbidden` JSON payloads.

---

## 📋 Reusing for Different Projects (What to Change)

When copying or cloning this gateway for a new project, you only need to modify [`src/main/resources/application.properties`](file:///home/sameer-wadekar/Desktop/WorkFlow/api-gateway/src/main/resources/application.properties):

1. **Routes (`spring.cloud.gateway.routes`)**:
   - Point route IDs, paths, and URIs to your target microservices:
     ```properties
     spring.cloud.gateway.routes[0].id=my-service-route
     spring.cloud.gateway.routes[0].uri=http://localhost:8081
     spring.cloud.gateway.routes[0].predicates[0]=Path=/api/myservice/**
     ```
2. **Public Paths (`app.security.public-paths`)**:
   - Add routes that do not require authentication:
     ```properties
     app.security.public-paths=/auth/**,/api/auth/**,/public/**,/actuator/**
     ```
3. **Public Key Source**:
   - If using RSA PEM: place your `public.pem` in `keys/public.pem` or point `spring.security.oauth2.resourceserver.jwt.public-key-url` to your auth service.
   - If using Keycloak/Okta/Auth0: uncomment `spring.security.oauth2.resourceserver.jwt.jwk-set-uri`.

---

## 🛠️ Build & Test

```bash
# Build & Run Tests
./mvnw clean test

# Run Locally
./mvnw spring-boot:run
```
# api-gateway-template
