# ==============================================================================
# File: Dockerfile
# Description: Dockerfile to containerize the cybersecurity ATT&CK Streamlit application.
# To Build: `docker build -t cybersecurity-attack-app .`
# To Run: `docker run -p 8501:8501 --env-file .env cybersecurity-attack-app`
# ==============================================================================
FROM python:alpine3.22

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

HEALTHCHECK CMD streamlit healthcheck

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
