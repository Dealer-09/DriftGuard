# Scenario 02 — All Dockerfile Issues
# Expected standalone Dockerfile findings:
#   DF-01: No USER (running as root)
#   DF-02: Base image uses :latest
#   DF-03: Hardcoded secret in ENV
#   DF-04: ADD used instead of COPY
#   DF-05: No HEALTHCHECK

FROM python:latest

WORKDIR /app

ADD . /app

ENV DB_PASSWORD=supersecret123
ENV API_SECRET_KEY=hardcoded-key-abc

RUN pip install -r requirements.txt

EXPOSE 8000

CMD ["python", "app.py"]
