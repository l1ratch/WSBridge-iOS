# WSBridge Relay — WS-мост iPhone -> VDS -> Telegram kws (IPv6).
#
# Цели (требования владельца): стабильность, самоподъём, минимум ресурсов
# (2-5 клиентов), максимум деталей при ошибках. Итог:
#   - образ ~55 МБ (python:3.12-alpine), зависимостей нет;
#   - один процесс, non-root, лимит памяти 96 МБ в compose;
#   - статистика/ключ/диагностика на volume /data — переживают рестарт;
#   - healthcheck: relay.py doctor (ключ+IPv6+DNS);
#   - restart: unless-stopped.
FROM python:3.12-alpine

# Никаких apk-пакетов: только стандартная библиотека Python.
RUN adduser -D -H -u 10001 relay

WORKDIR /app
COPY mtproto.py state.py relay.py /app/

# /data — volume для ключа, статистики и diag.log
RUN mkdir -p /data && chown relay:relay /data
VOLUME /data

USER relay
EXPOSE 2087

ENV PYTHONUNBUFFERED=1

# SIGTERM -> graceful stop (stats flush, diag event)
STOPSIGNAL SIGTERM

ENTRYPOINT ["python3", "/app/relay.py"]
# Базовый запуск; порт меняется через аргументы docker run
CMD ["--port", "2087", "--data-dir", "/data"]
