# Scenario 05 — Minimal Drift Demo (DRIFT-01 + DRIFT-03 only)
# Best for a quick 30-second demo: just two drift rules, easy to explain.
#
# Story: "Developer pinned the base image and set a non-root user.
#         The K8s deployment un-pins the image AND runs it as root.
#         Your CI passed. Your runtime is insecure."

FROM node:20.11.0-alpine3.19

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && \
    addgroup -S app && adduser -S app -G app
COPY --chown=app:app . .

HEALTHCHECK CMD wget -qO- http://localhost:3000/ || exit 1

USER app
EXPOSE 3000
CMD ["node", "index.js"]
