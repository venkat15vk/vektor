FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate data, normalize, run models, run reasoning, then start API
RUN python generate_data.py && \
    python normalize.py && \
    python run_models.py && \
    python reason.py

EXPOSE 8000

CMD ["python", "api.py"]
