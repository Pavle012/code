# syntax=docker/dockerfile:1

FROM rust:1.80-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev git && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --bin labrinth

FROM debian:bookworm-slim AS runner
LABEL org.opencontainers.image.source=https://github.com/modrinth/code
LABEL org.opencontainers.image.title=labrinth
LABEL org.opencontainers.image.description="Modrinth API"
LABEL org.opencontainers.image.licenses=AGPL-3.0-only

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates dumb-init curl \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/labrinth /labrinth/labrinth
COPY apps/labrinth/migrations /labrinth/migrations
COPY apps/labrinth/assets /labrinth/assets

WORKDIR /labrinth
ENTRYPOINT ["dumb-init", "--"]
CMD ["/labrinth/labrinth"]
