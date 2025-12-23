FROM python:3.9-slim
WORKDIR /app
COPY hashx4_yam.py .
CMD ["python", "hashx4_yam.py"]
