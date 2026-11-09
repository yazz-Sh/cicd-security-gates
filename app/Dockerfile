FROM python:3.12.0-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
ENV DB_PASSWORD=Sup3rS3cret!2026
EXPOSE 8000
CMD ["uvicorn", "facturation.main:app", "--host", "0.0.0.0", "--port", "8000"]