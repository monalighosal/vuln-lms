# Vulnerable Learning Management System (vuln-lms)

A deliberately vulnerable Learning Management System designed for security training and penetration testing purposes. This application contains various security vulnerabilities that are commonly found in web applications to help security professionals and developers learn about common security flaws.

## Overview

This application is intentionally insecure and should **never** be deployed in a production environment. It is designed to showcase common web application vulnerabilities in a controlled learning environment.

## Security Vulnerabilities

This application contains the following security vulnerabilities:

- **SQL Injection (SQLi)**: Direct concatenation of user input in SQL queries
- **Insecure Direct Object Reference (IDOR)**: Lack of proper access controls allowing access to other users' resources
- **Broken Authentication**: Access to admin functions without proper authentication
- **Cross-Site Scripting (XSS)**: Unsanitized user input in comments
- **Information Disclosure**: Detailed error messages exposing internal details
- **Mass Assignment**: Allowing updates to any user field
- **Prototype Pollution**: Vulnerable to prototype pollution via the preferences endpoint
- **Broken Access Control**: Bypassing authorization checks

## Prerequisites

- Node.js (version 14 or higher)
- npm (Node package manager)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vuln-lms.git
cd vuln-lms
```

2. Install dependencies:
```bash
npm install
```

3. Initialize the database:
```bash
node init-db.js
```

## Running the Application

```bash
npm start
# or
node server.js
```

The application will start on port 5000 by default and be accessible at `http://localhost:5000`

## Default Credentials

The application comes with default user accounts for testing:

- **Admin User**: `admin` / `admin123`
- **Regular Users**: `test1` / `password123`, `test2` / `password123`

## Available Endpoints

- **Home**: `http://localhost:5000/`
- **Login**: `http://localhost:5000/login`
- **Registration**: `http://localhost:5000/register`
- **User Dashboard**: `http://localhost:5000/dashboard`
- **Admin Panel**: `http://localhost:5000/admin`
- **Courses**: `http://localhost:5000/courses`

## Vulnerability Testing Guide

### SQL Injection Testing
- Try payloads like `' OR 1=1--` in login fields
- Example: Username: `admin'--`, Password: `anything`

### IDOR Testing
- After logging in, try accessing other users' dashboards by changing the user ID in the URL
- Example: `/dashboard/2` when logged in as user 1

### Broken Authentication Testing
- Try accessing `/admin` without logging in
- The admin panel is accessible without authentication

### XSS Testing
- Submit JavaScript in the comment field: `<script>alert('XSS')</script>`
- This should execute when the comment is displayed

### Prototype Pollution Testing
- Send a POST request to `/api/preferences` with payload containing `__proto__` or `constructor` properties
- Example payload: `{"__proto__":{"polluted":"value"}}`

### Mass Assignment Testing
- Try updating user roles by sending additional fields in profile updates
- Example: Update profile with `{"role": "admin"}` to escalate privileges

## Application Structure

```
vuln-lms/
├── public/                 # Static files (HTML, CSS, JS)
│   ├── admin.html          # Admin panel UI
│   ├── dashboard.html      # User dashboard
│   ├── login.html          # Login page
│   ├── register.html       # Registration page
│   ├── user-profile.html   # User profile page
│   └── style.css           # Styling
├── server.js               # Main application server
├── config.js               # Configuration settings
├── init-db.js              # Database initialization
├── security.js             # Security helper functions
├── package.json            # Dependencies and scripts
└── README.md               # This file
```

## Database

The application uses SQLite for data storage. The database file is created automatically when you run `init-db.js`.

## Important Security Notice

⚠️ **WARNING**: This application is intentionally vulnerable and should never be deployed in any production environment. It is designed solely for educational and security testing purposes in controlled environments.

## License

This project is intended for educational purposes only. Use responsibly for learning and testing security concepts.