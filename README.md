
# Authentication Page

A Node.js authentication application with email OTP verification,
MongoDB persistence, secure password hashing and login sessions.

## Requirements

- Node.js 20+
- MongoDB Atlas account
- SMTP email account or email provider

## Run locally

1. Install dependencies:

   npm install

2. Copy `.env.example` to `.env`.

3. Add your MongoDB URI, JWT secret and SMTP credentials.

4. Start the server:

   npm start

5. Open:

   http://localhost:3000

## Registration flow

1. Enter name, email, mobile (optional) and password.
2. Click Verify next to the email field.
3. Enter the six-digit OTP in the popup.
4. Click Verify OTP.
5. Click Continue & Create Account.
6. The verified account is saved to MongoDB.

## Security notes

- Passwords are hashed with bcrypt.
- OTPs are stored as hashes.
- OTPs expire after 10 minutes.
- Incorrect OTP attempts are limited.
- The final account is created only after email verification.
- Never commit `.env` or production secrets to GitHub.
- Keep DEV_SHOW_OTP=false in production.

## Deploy

Push the repository to GitHub and deploy it as a Node web service on Render.
Set the required environment variables in the Render dashboard.
Create a MongoDB Atlas database and allow the deployed service to connect.
