
# Auth Backend API

## Project Overview

This is an authentication backend built with NestJS and MongoDB (using Mongoose) providing secure user management functionality. It supports signup, login, password reset, email verification via OTP, JWT access & refresh tokens, and avatar upload.

---

## Features / Functionality

* User Signup with email & password (hashed with bcrypt)
* Email verification via OTP
* User Login with JWT token issuance (access + refresh tokens)
* Refresh token handling for session management
* Password change and reset (forgot password flow via email)
* Email verification status check
* Upload and retrieve user avatar
* Secure password hashing and validation
* Token expiry and revocation
* Error handling with meaningful exceptions

---

## Installation & Setup

```bash
git clone https://github.com/yourusername/auth-backend.git
cd auth-backend
npm install
```

Configure your environment variables :
## create a folder in src 

```bash
mkdir config
cd config
touch config.ts
```

```bash
import { registerAs } from '@nestjs/config';

export default registerAs('app', () => ({
  MONGODB_URI: '',

  jwt: {
    secret: '',
  },

  email: {
    user: '',
    pass: '',
    from: '',
  },

  backendUrl: 'http://localhost:5000',
  },

```

Run the app:

```bash
npm run start:dev
```

The backend will run at: `http://localhost:5000`

---

## API Endpoints

| Method | Endpoint                  | Description                       | Request Body / Params                         |
| ------ | ------------------------- | --------------------------------- | --------------------------------------------- |
| POST   | `/auth/signup`            | Register new user                 | `{ name, email, password }`                   |
| POST   | `/auth/login`             | User login                        | `{ email, password }`                         |
| POST   | `/auth/verify-email`      | Verify user email with OTP        | `{ email, code }`                              |
| POST   | `/auth/refresh-token`     | Get new access and refresh tokens | `{ refreshToken }`                            |
| POST   | `/auth/change-password`   | Change user password              | `{ oldPassword, newPassword }`        |
| POST   | `/auth/forgot-password`   | Initiate password reset           | `{ email }`                                   |
| POST   | `/auth/reset-password`    | Reset password with reset token   | `{ resetToken, newPassword }`                 |
| POST   | `/auth/upload-avatar`     | Upload user avatar image          | form-data: `file` (image), header: Auth token |
| GET    | `/auth/get-avatar/:email` | Get user avatar by email          | URL param: `email`                            |

---

## Testing With Postman

* Use POST method for all `/auth` endpoints.
* For image upload, use **form-data** body with key `file` (type: file).
* Add `Authorization: Bearer <your_jwt_token>` header for protected routes like avatar upload.
* Use JSON body for others as specified above.
* Tokens (`accessToken` and `refreshToken`) are returned on successful login and refresh.

---

## Example Signup Request

```
POST /auth/signup
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "Password123"
}
```

---

## Example Login Request

```
POST /auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "Password123"
}
```

---

## Notes

* Passwords are hashed with bcrypt for security.
* JWT tokens expire in 7 days.
* Refresh tokens are stored in the database with expiry.
* Email verification required before login.
* Password reset tokens expire after 7 days.
* Avatar uploads supported with Multer middleware.

