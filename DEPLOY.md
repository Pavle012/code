# Deploying Modrinth Server Hosting

This guide describes the easiest ways to deploy the Modrinth Server Hosting Backend (`labrinth`) and the Web Frontend.

---

## Method 1: All-in-One Docker Compose (Recommended)

This is the easiest way to deploy the entire stack (databases, server hosting backend, and the web frontend) in a single command.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Steps
1. **Configure Environment Variables (Optional)**
   The web frontend is pre-configured to use `api.modrinth.com` for downloading mods/packs, and point server actions to the local hosting backend at `http://localhost:8000/`. If you want to change the server hosting URL, customize the `PYRO_BASE_URL` environment variable inside [docker-compose.yml](file:///home/pavle/code/forks/modrinthosting/docker-compose.yml):
   ```yaml
   frontend:
     environment:
       - BROWSER_BASE_URL=https://api.modrinth.com/v2/
       - PYRO_BASE_URL=http://your-domain.com:8000/
   ```

2. **Run Docker Compose**
   In the root directory of the repository, execute:
   ```bash
   docker compose up --build -d
   ```
   This will:
   - Build and start the PostgreSQL, Redis, Clickhouse, Typesense, Meilisearch, and Mail services.
   - Compile and start the Rust `labrinth` backend server on port `8000`.
   - Build and start the Nuxt 3 web frontend on port `3000`.

3. **Access Services**
   - **Web Frontend**: `http://localhost:3000`
   - **Backend API**: `http://localhost:8000`

---

## Method 2: Hybrid Dev/Deploy (Docker Databases + Host Apps)

Use this method if you want to run the applications directly on your host machine (for debugging or lighter system overhead), while utilizing Docker for the database backend suites.

### Steps

1. **Start Databases via Compose**
   Launch only the required databases:
   ```bash
   docker compose up postgres_db redis clickhouse typesense0 meilisearch0 -d
   ```

2. **Deploy/Run Backend (`labrinth`)**
   - Install Rust (1.80+).
   - Ensure database env variables are configured. (You can copy and edit the defaults from [apps/labrinth/.env.local](file:///home/pavle/code/forks/modrinthosting/apps/labrinth/.env.local) to a `.env` file).
   - Run:
     ```bash
     cargo run --release --bin labrinth
     ```

3. **Deploy/Run Web Frontend**
   - Install Node.js v24+ and pnpm.
   - Install dependencies:
     ```bash
     pnpm install
     ```
   - Build and run:
     ```bash
     # To run in Dev Mode:
     pnpm --filter @modrinth/frontend dev
     
     # Or Build & Run in Production Mode:
     pnpm --filter @modrinth/frontend build
     node apps/frontend/.output/server/index.mjs
     ```
