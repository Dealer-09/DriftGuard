# ─── HARDENED DOCKERFILE ───────────────────────────────────────────────
# This Dockerfile does everything right:
#   ✓ Pinned base image
#   ✓ Non-root USER
#   ✓ HEALTHCHECK
#   ✓ No secrets
#   ✓ COPY not ADD
# The paired K8s manifest (demo-k8s-bad.yaml) silently undoes 4 of these.
# ────────────────────────────────────────────────────────────────────────

FROM node:20.11.0-alpine3.19

WORKDIR /app

# Install dependencies first (cache layer)
COPY package*.json ./
RUN npm ci --only=production

# Copy application source
COPY src/ ./src/

# Create non-root user — this is the hardening the K8s manifest will undo
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

# HEALTHCHECK — the K8s manifest will drop this too
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

# Switch to non-root user
USER appuser

EXPOSE 3000

CMD ["node", "src/server.js"]
