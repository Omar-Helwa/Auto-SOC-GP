# AutoSOC Blue role as an HTTP service.
# Build (from the repo root):  docker build -t autosoc-blue 03_blue_role
# Run:                         docker run -p 8080:8080 autosoc-blue
# Real model: add  -e BLUE_MODEL_PROVIDER=anthropic -e ANTHROPIC_API_KEY=...  (never bake keys in the image)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY autosoc_blue ./autosoc_blue
RUN pip install --no-cache-dir ".[http,anthropic,openai]" \
 && useradd --create-home blue
USER blue

EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["uvicorn", "--factory", "autosoc_blue.api:create_app", "--host", "0.0.0.0", "--port", "8080"]
