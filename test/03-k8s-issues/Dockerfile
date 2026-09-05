# Scenario 03 — Clean Dockerfile (testing K8s issues only)

FROM node:20.11.0-alpine3.19
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY src/ ./src/
RUN adduser --system --uid 1001 appuser
HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1
USER appuser
EXPOSE 3000
CMD ["node", "src/server.js"]
