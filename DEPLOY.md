# Deploying Modrinth Server Hosting
This guide describes the easiest ways to deploy the Modrinth Server Hosting Backend (`labrinth`) and the Web Frontend.

---

## Prerequisites

### Docker Desktop (Recommended for most users)
Docker Desktop bundles both Docker and Docker Compose in a single install, making it the easiest way to get started.

1. Download and install Docker Desktop for your platform:
   - **Windows**: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
   - **macOS**: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
   - **Linux**: [Docker Desktop for Linux](https://docs.docker.com/desktop/install/linux-install/)
2. Launch Docker Desktop and wait for the Docker engine to fully start (the whale icon in the system tray should be steady, not animated).
3. Verify the installation by opening a terminal and running:
   ```bash
   docker --version
   docker compose version
   ```
   Both commands should print version numbers. No separate Docker Compose install is needed.

### Manual Install (Linux servers / headless environments)
If you're running a server without a desktop environment, install Docker Engine and the Compose plugin separately:
- [Docker Engine](https://docs.docker.com/engine/install/)
- [Docker Compose plugin](https://docs.docker.com/compose/install/)

---

## Method 1: All-in-One Docker Compose (Recommended)

This is the easiest way to deploy the entire stack (databases, server hosting backend, and the web frontend) in a single command.

### Steps

1. **Configure Environment Variables (Optional)**
   The web frontend is pre-configured to use `api.modrinth.com` for downloading mods/packs, and point server actions to the local hosting backend at `http://localhost:8000/`. If you want to change the server hosting URL, customize the `PYRO_BASE_URL` environment variable inside `docker-compose.yml`:
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

   > **Docker Desktop tip:** You can also open the repository folder in Docker Desktop's GUI, which will detect the `docker-compose.yml` and let you start the stack with a single click from the **Containers** tab.

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
   > **Docker Desktop tip:** After running the above command, you can monitor the individual database containers in the **Containers** panel in Docker Desktop — useful for checking logs or restarting a specific service.

2. **Deploy/Run Backend (`labrinth`)**
   - Install Rust (1.80+).
   - Ensure database env variables are configured. (You can copy and edit the defaults from `apps/labrinth/.env.local` to a `.env` file).
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
