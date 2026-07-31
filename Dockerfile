FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    POETRY_VERSION=1.8.2 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false

# Instalar dependências de sistema necessárias
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Instalar Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

ENV PATH="$POETRY_HOME/bin:$PATH"

WORKDIR /app

# Copiar manifesto de dependências e lockfile
COPY pyproject.toml poetry.lock /app/

# Instalar dependências da aplicação com setuptools=69.5.1 reproduzível
RUN poetry install --no-interaction --no-ansi --no-root

# Copiar código fonte
COPY . /app/

# Instalar o próprio pacote
RUN poetry install --no-interaction --no-ansi

CMD ["poetry", "run", "python", "scripts/correlation_worker.py"]
