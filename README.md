# CloudOTP

A secure TOTP/2FA sharing dashboard powered by Cloudflare Workers and D1.

CloudOTP is designed for privately managing shared 2FA codes. Administrators can save authorized account TOTP secrets, generate secure sharing links, and allow users to view current six-digit codes without exposing the original secret.

> Use this only for accounts or services you are authorized to manage. TOTP sharing links are sensitive credentials. Do not publish them publicly.

## Features

- Admin login
- Member and account management
- Six-digit TOTP code generation
- 30-second countdown
- Independent sharing link for each member
- Share link enable, disable, and reset
- Category and status filtering
- Access logs
- Light and dark themes
- Encrypted TOTP secret storage
- Cloudflare Workers deployment
- Cloudflare D1 database
- One-click Deploy to Cloudflare support

## Deployment

This repository is intended to support one-click deployment to Cloudflare Workers.

The Cloudflare version is being prepared.
