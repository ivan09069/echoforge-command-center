FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir \
    anthropic \
    openai \
    google-genai \
    "mcp[cli]" \
    httpx \
    fastapi \
    uvicorn \
    websockets
COPY . .
EXPOSE 8000 8002
