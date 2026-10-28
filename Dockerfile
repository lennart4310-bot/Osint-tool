FROM python:3.12-slim
WORKDIR /app
COPY handle_hunt.py .
ENV HOST=0.0.0.0 PORT=7860 TRUST_PROXY=1
EXPOSE 7860
CMD ["python3", "handle_hunt.py"]
