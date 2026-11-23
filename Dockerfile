FROM python:3.12-slim
WORKDIR /app
RUN useradd --system --uid 10001 tracker && mkdir /data && chown tracker /data
COPY app.py .
COPY static ./static
ENV TRACKER_HOST=0.0.0.0 TRACKER_DB=/data/tracker.sqlite3 PYTHONUNBUFFERED=1
USER tracker
EXPOSE 8080
CMD ["python", "app.py"]
