
---

### ✅ **Structure**
1. **Installation & Setup**
2. **Available Routes**
3. **Authentication Workflow**
4. **How the API Gateway Works**
5. **Functionality & Integration with Microservices**

---

```markdown
# 🛡️ FastAPI Auth Gateway – Keycloak Integration

This gateway handles secure access control and routing between the frontend and various backend services in a microservices architecture. It acts as the central authentication layer using Keycloak and protects internal APIs based on user roles and access tokens.

---

## ⚙️ 1. Installation & Setup

### ✅ Requirements
- Python 3.10+
- A running Keycloak instance [Docker]
- Internal microservices available on the network

### 🔧 Setup Steps

```bash
# Clone the repository
git clone https://github.com/hejjiouiy/api-gateway
cd api-gateway

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload

```

> 🧠 Ensure your `.env` file is configured with the correct Keycloak realm, client ID, and secrets.

---

## 🚀 2. Available Routes

| Route           | Method | Description |
|-----------------|--------|-------------|
| `/login`        | GET    | Redirects to Keycloak login page |
| `/callback`     | GET    | Handles redirection from Keycloak after login, fetches tokens |
| `/logout`       | GET    | Logs the user out of both the gateway and Keycloak |
| `/refresh`      | GET    | Refreshes the access token using a valid refresh token |
| `/user-info`    | GET    | Returns basic profile and role info of the currently logged-in user |
| `/admin`        | GET    | Protected route, accessible only to users with `admin` role |
| `/forward-to-service` | GET | Sample endpoint to forward a request to an internal microservice with a valid internal token |

---

## 🔐 3. Authentication Workflow

1. **User requests `/login`**  
   They are redirected to Keycloak for authentication.

2. **Keycloak redirects to `/callback?code=...`**  
   The server exchanges the code for access and refresh tokens.

3. **Tokens are stored**  
   Either in HTTP-only cookies or managed client-side (based on implementation).

4. **Every request to protected routes checks the token**  
   If valid, user info is extracted; if not, the request is rejected.

5. **Refresh flow**  
   When the access token expires, the `/refresh` route allows clients to renew it using the refresh token.

6. **Check Connected User**  
   The Connected user Infos Can be retrieved from the `/profile` route with roles and basic auth values.

---

## 🔄 4. How the API Gateway Works

The gateway is the **authentication and authorization layer** between the frontend and backend services.

### 🧩 Responsibilities

- Authenticate users through Keycloak (OAuth2)
- Protect endpoints using role-based access control
- Forward verified requests to internal services
- Generate internal tokens for downstream services
- Validate all incoming tokens

### 🗂️ Token Handling

- **Access Token**: Used to identify and authorize the user.
- **Internal Token**: Short-lived token generated after authentication and attached to proxied requests to internal services.
- **Refresh Token**: Used to renew access tokens without requiring the user to log in again.

---

## 🔗 5. Functionality & Integration with Microservices

This gateway is the **entry point** to the system. Once a user is authenticated:

- An **internal token** is generated with essential user information (ID, roles).
- That token is used to call **internal APIs** securely.
- The microservices **do not handle authentication themselves**, but only validate the internal token.
- This ensures a clear **separation of concerns**:  
  - **Gateway** = security, auth, role enforcement  
  - **Services** = business logic, trusting only the gateway

### 📡 Communication Flow

```
Frontend → Gateway → Keycloak (login)
         → Gateway → Internal Service (with internal token)
         ← Gateway ← Internal Service Response
         ← Frontend ← Gateway Response
```

---

## 🧪 Example Use Case

A user logs in → visits the dashboard → requests a protected resource:

- They authenticate via Keycloak.
- Gateway validates their role (e.g., `admin`).
- If allowed, the gateway forwards the request to the right service.
- Internal services respond based on the embedded token info (like user ID or roles).

---

## 📬 Developer Notes

- The gateway protects all routes — no direct access to services is allowed.
- Rate limiting and token expiration are handled centrally.
- Extendable for multi-client support or service discovery as needed.

---

## 📂 Contact

Feel free to reach out to the backend team if you’re integrating a new service behind the gateway or need token structure details.

```

---

Let me know if you want to export this as a file or need diagrams (sequence or architecture).