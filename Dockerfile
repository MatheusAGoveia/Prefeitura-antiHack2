FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VERSION=1.8.2 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    PATH="/app/.venv/bin:/opt/poetry/bin:$PATH"

# Instalar dependências de sistema necessárias
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalar Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

WORKDIR /app

# Copiar manifesto de dependências e lockfile
COPY pyproject.toml poetry.lock /app/

# Instalar dependências da aplicação com setuptools=69.5.1 reproduzível no virtualenv /app/.venv
RUN poetry install --no-interaction --no-ansi --no-root && \
    /app/.venv/bin/pip install --no-cache-dir setuptools==69.5.1

# Copiar código fonte
COPY . /app/

# Instalar o próprio pacote
RUN poetry install --no-interaction --no-ansi

CMD ["/app/.venv/bin/python", "scripts/correlation_worker.py"]
