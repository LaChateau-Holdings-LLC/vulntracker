FROM python:3.12-slim
WORKDIR /app
RUN useradd --system --uid 10001 tracker && mkdir /data && chown tracker /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py tracker_auth.py .
COPY static ./static
ENV TRACKER_HOST=0.0.0.0 TRACKER_DB=/data/tracker.sqlite3 PYTHONUNBUFFERED=1
USER tracker
EXPOSE 8080
CMD ["python", "app.py"]
