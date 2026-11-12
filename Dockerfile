FROM python:3.13-slim

LABEL org.opencontainers.image.title="SiteSentry" \
      org.opencontainers.image.description="Passive website security scanner" \
      org.opencontainers.image.source="https://github.com/vicuvi1/SiteSentry" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY sitesentry ./sitesentry
RUN pip install --no-cache-dir . && useradd --create-home --uid 10001 scanner

# Run as an unprivileged user
USER scanner
EXPOSE 8765

ENTRYPOINT ["sitesentry"]
CMD ["--help"]
