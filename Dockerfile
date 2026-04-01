FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsup.config.ts ./
COPY src ./src

RUN npm run build
RUN npm prune --omit=dev

FROM node:20-alpine

ENV NODE_ENV=production
ENV MCP_TRANSPORT=http
ENV PORT=3000
ENV MCP_HOST=0.0.0.0
ENV MCP_PATH=/mcp

WORKDIR /app

COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/build ./build

EXPOSE 3000

CMD ["node", "build/index.js"]
