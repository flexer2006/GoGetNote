FROM redis:7.4.2-alpine3.21

HEALTHCHECK --interval=5s --timeout=5s --retries=3 CMD redis-cli ping || exit 1