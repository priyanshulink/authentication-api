# Authentication API

JWT-based authentication system with Node.js, Express, and MongoDB.

## Features
- User signup/login with JWT tokens
- Password hashing with bcrypt
- Cookie-based authentication
- Role-based authorization (Student/Admin)
- Protected routes

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create `.env` file:
```
PORT=4000
MONGODB_URL=your_mongodb_connection_string
JWT_SECRET=your_secret_key
```

3. Run the server:
```bash
npm start
```

## API Endpoints

- `POST /api/v1/signup` - Register new user
- `POST /api/v1/login` - Login user
- `GET /api/v1/test` - Protected route (requires auth)
- `GET /api/v1/student` - Student-only route
- `GET /api/v1/admin` - Admin-only route
