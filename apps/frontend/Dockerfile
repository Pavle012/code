# syntax=docker/dockerfile:1
FROM node:24-alpine AS builder
WORKDIR /app
RUN npm install -g pnpm
COPY . .
RUN pnpm install
RUN pnpm --filter @modrinth/frontend build

FROM node:24-alpine AS runner
WORKDIR /app
COPY --from=builder /app/apps/frontend/.output ./
EXPOSE 3000
ENV PORT=3000
ENV HOST=0.0.0.0
CMD ["node", "server/index.mjs"]
