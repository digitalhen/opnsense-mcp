FROM node:22-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production=false

COPY tsconfig.json ./
COPY src/ ./src/

RUN npx tsc
RUN npm prune --production

EXPOSE 3100

CMD ["node", "dist/server.js"]
