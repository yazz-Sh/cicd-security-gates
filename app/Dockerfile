# CORRECTIFS image :
#  - image de base recente, epinglee par empreinte (digest) et non par tag modifiable
#  - multi-etapes : aucun outil de build dans l'image finale
#  - utilisateur non-root 10001, HEALTHCHECK, aucun secret dans l'image
ARG BASE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

FROM ${BASE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM ${BASE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=build /install /usr/local
COPY facturation/ ./facturation/
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"]
CMD ["uvicorn", "facturation.main:app", "--host", "0.0.0.0", "--port", "8000"]