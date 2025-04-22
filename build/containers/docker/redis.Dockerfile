FROM redis:7.4.2-alpine3.21

EXPOSE 6379

CMD ["redis-server", "--appendonly", "yes"]