# WSBridge WS-мост: iPhone (IPv4) -> VDS -> kws Telegram (IPv6).
# Образ ~55 МБ, зависимостей нет (только stdlib Python).
FROM python:3.12-alpine

# Никаких пакетов не ставим: скрипт использует только стандартную библиотеку.
# Непривилегированный пользователь — процесс не должен быть root.
RUN adduser -D -H -u 10001 bridge

WORKDIR /app
COPY wsb-ws-bridge.py /app/wsb-ws-bridge.py

USER bridge
EXPOSE 8443

# IPv6 нужен только для ИСХОДЯЩИХ соединений VDS -> Telegram.
# Входящий порт слушается по IPv4 (0.0.0.0), телефону IPv6 не требуется.
ENTRYPOINT ["python3", "/app/wsb-ws-bridge.py"]
CMD ["--port", "8443"]
