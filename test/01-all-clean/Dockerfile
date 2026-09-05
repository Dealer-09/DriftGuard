# Scenario 01 — All Clean
# Expected: Hardening Score 100, Intent Preservation 100, Verdict PASS
# No findings should be generated.

FROM node:20.11.0-alpine3.19

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY src/ ./src/

RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

USER appuser

EXPOSE 3000

CMD ["node", "src/server.js"]
