# Intentionally bad Dockerfile for CONFIG-DOCKER-* rules.
FROM node:latest
ENV API_SECRET=fixture-not-a-real-secret
WORKDIR /app
COPY . .
# no USER directive → runs as root
CMD ["node", "src/index.js"]
