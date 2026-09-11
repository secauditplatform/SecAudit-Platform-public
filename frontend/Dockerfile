# Development target (lab Compose) and production nginx image.
# docker compose (lab):  target: development
# prod compose / Helm:   target: production (default)

FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
# Same-origin /api in production; Keycloak URL is build-time for the SPA.
ARG VITE_AUTH_ENABLED=true
ARG VITE_LOCAL_AUTH_ENABLED=false
ARG VITE_DEMO_MODE=false
ARG VITE_SSO_ENABLED=true
ARG VITE_SHOW_SSO_BUTTON=true
ARG VITE_KEYCLOAK_URL=
ARG VITE_KEYCLOAK_REALM=secaudit
ARG VITE_KEYCLOAK_CLIENT_ID=secaudit-frontend
ENV VITE_AUTH_ENABLED=$VITE_AUTH_ENABLED \
    VITE_LOCAL_AUTH_ENABLED=$VITE_LOCAL_AUTH_ENABLED \
    VITE_DEMO_MODE=$VITE_DEMO_MODE \
    VITE_SSO_ENABLED=$VITE_SSO_ENABLED \
    VITE_SHOW_SSO_BUTTON=$VITE_SHOW_SSO_BUTTON \
    VITE_KEYCLOAK_URL=$VITE_KEYCLOAK_URL \
    VITE_KEYCLOAK_REALM=$VITE_KEYCLOAK_REALM \
    VITE_KEYCLOAK_CLIENT_ID=$VITE_KEYCLOAK_CLIENT_ID
RUN npm run build

FROM node:22-alpine AS development
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

FROM nginx:1.27-alpine AS production
RUN apk add --no-cache curl \
    && deluser nginx 2>/dev/null || true \
    && addgroup -g 1000 -S secaudit \
    && adduser -S -D -H -u 1000 -G secaudit secaudit \
    && mkdir -p /var/cache/nginx /var/run /tmp/nginx \
    && chown -R secaudit:secaudit /var/cache/nginx /var/run /tmp/nginx /usr/share/nginx/html \
    && touch /tmp/nginx/nginx.pid \
    && chown secaudit:secaudit /tmp/nginx/nginx.pid
COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 1000:1000
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/ || exit 1
CMD ["nginx", "-g", "daemon off;"]
