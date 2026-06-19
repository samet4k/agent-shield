FROM rust:1.80-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p agentshield-cli -p agentshield-daemon -p agentshield-mcp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates bash curl && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m agentshield
COPY --from=builder /app/target/release/agentshield /usr/local/bin/agentshield
COPY --from=builder /app/target/release/agentshield-daemon /usr/local/bin/agentshield-daemon
COPY --from=builder /app/target/release/agentshield-mcp /usr/local/bin/agentshield-mcp
COPY policies/default.yml /etc/agentshield/policy.yml
ENV SHELL=/usr/local/bin/agentshield
ENV AGENTSHIELD_AGENT=docker
USER agentshield
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD agentshield status --format json || exit 1
ENTRYPOINT ["/usr/local/bin/agentshield"]
CMD ["--help"]