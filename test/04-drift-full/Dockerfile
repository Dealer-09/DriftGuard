# Scenario 04 — All 7 Drift Rules Fire
# Paste this Dockerfile + the k8s.yaml together.
# Expected drift findings: DRIFT-01 through DRIFT-07

# Dockerfile is fully hardened:
#   - Pinned base image (distroless) → triggers DRIFT-05, DRIFT-07
#   - USER nonroot                   → triggers DRIFT-01
#   - EXPOSE 8080                    → triggers DRIFT-02
#   - HEALTHCHECK                    → triggers DRIFT-04
#   - No secrets in ENV              → triggers DRIFT-06
#   - Pinned image                   → triggers DRIFT-03

FROM gcr.io/distroless/nodejs20-debian12:nonroot

WORKDIR /app

COPY --from=build /app/dist ./dist

HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:8080/health || exit 1

USER nonroot

EXPOSE 8080

CMD ["dist/server.js"]
