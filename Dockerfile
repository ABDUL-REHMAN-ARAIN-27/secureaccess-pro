# SecureAccess Pro - container image (works on Hugging Face Spaces, Railway,
# Fly.io, or any Docker host). Serves the web app + API on port 7860.
FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r backend/requirements.txt

# Seed demo accounts + patients on first boot.
ENV AUTO_SEED=true
# Write the SQLite DB to a writable location.
ENV DATABASE_URL=sqlite:////tmp/secureaccess_pro.db

EXPOSE 7860
CMD ["gunicorn", "--chdir", "backend", "app:app", \
     "--bind", "0.0.0.0:7860", "--workers", "1", "--timeout", "120"]
