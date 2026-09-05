# Scenario 06 — Real-world Node.js Microservice
# Realistic mixed bag — not obviously wrong, subtle issues.
# Expected findings: DF-02 (no digest), DF-05 (no HEALTHCHECK), K8S-03, DRIFT-01, DRIFT-04

FROM node:20-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN addgroup -S nodegroup && adduser -S nodeuser -G nodegroup

USER nodeuser

EXPOSE 8080

CMD ["node", "server.js"]
