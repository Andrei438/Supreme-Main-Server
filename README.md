# Supreme Main Server

High-performance FastAPI backend for token management, file distribution, and real-time logging.

## Features
- **Token System**: Generation and validation via MySQL and XenForo API.
- **Secure Downloads**: HWID-locked file distribution for `client.exe`.
- **Real-time Monitoring**: Live log streaming via Redis Pub/Sub.
- **Admin Dashboard**: Secure management UI with TOTP authentication.
- **Atomic Updates**: Secure API endpoint to update the loader without restarts.

## Dokploy Deployment
1. Push this repository to a private GitHub repo.
2. In Dokploy, create a **Compose** service using the root `docker-compose.yml`.
3. Set environment variables based on `.env.example`.
4. Add the domain `cloud.supreme-cheats.xyz` with SSL.

## Tech Stack
- **Language**: Python 3.11 (FastAPI)
- **Primary DB**: MySQL (External)
- **Logs DB**: SQLite (Persistent Volume)
- **Cache/Sessions**: Redis
- **Proxy**: Traefik (via Dokploy labels)
