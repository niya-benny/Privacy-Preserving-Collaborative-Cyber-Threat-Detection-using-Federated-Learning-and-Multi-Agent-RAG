# Build AFTER running steps 1-9 so artifacts/ and outputs/ exist. Ollama runs on the host, not in the container.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV OLLAMA_URL=http://host.docker.internal:11434
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
