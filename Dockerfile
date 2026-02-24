FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

ENV NODE_ENV=production

EXPOSE 4242

HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -qO- http://localhost:4242/health || exit 1

CMD ["node", "server.js"]
