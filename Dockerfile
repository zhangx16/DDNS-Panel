FROM ghcr.io/sagernet/sing-box:v1.14.4 AS singbox

FROM python:3.12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home panel \
    && install -d -m 0700 -o panel -g panel /data
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box

WORKDIR /app
COPY server.py start.sh ./
COPY static/ static/
ENV BIND=0.0.0.0 PORT=8787 DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1
USER panel
EXPOSE 8787
CMD ["/bin/sh", "/app/start.sh"]
