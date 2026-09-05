# Scenario 07 — Real-world Python / FastAPI Service
# Expected: DF-01 (no USER), DF-02 (no pinned tag), K8S-05 (literal secrets),
#           K8S-07 (allowPrivilegeEscalation), DRIFT-06 (clean DF, secrets in K8s)

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Developer forgot USER and HEALTHCHECK — common oversight

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
