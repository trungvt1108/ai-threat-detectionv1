# Optional containerized copy of the project fixture service (stdlib only, no app dependencies).
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 fixture
WORKDIR /app
COPY ai_threat_detection/__init__.py ai_threat_detection/__init__.py
COPY ai_threat_detection/lab/__init__.py ai_threat_detection/lab/__init__.py
COPY ai_threat_detection/lab/fixture_service.py ai_threat_detection/lab/fixture_service.py
USER fixture
EXPOSE 8080
CMD ["python", "-m", "ai_threat_detection.lab.fixture_service", "--container", "--host", "0.0.0.0", "--port", "8080", "--log-dir", "/logs", "--ready-file", "/logs/.fixture-ready.json"]
