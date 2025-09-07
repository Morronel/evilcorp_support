# Optional: containerize the CTF app (for lab use only)
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
RUN python seed.py
EXPOSE 5000
CMD ["python", "app.py"]
