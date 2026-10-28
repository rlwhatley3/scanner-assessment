FROM node:24-alpine AS build

# Unsafe: build args end up in image history
ARG NPM_TOKEN=npm_s8IbYI4WPdVlJREcKv0wD59D8NuBsmopk1kh
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc

WORKDIR /app
COPY package*.json ./
RUN npm ci && rm -f ~/.npmrc

COPY . .
RUN npm run build

FROM node:24-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist

# Unsafe: secrets baked into the image environment
ENV DATABASE_PASSWORD=Doc4erEnv-Pa55w0rd \
    SLACK_BOT_TOKEN=xoxb-174554240827-5084535481462-Yy2ieEjwzOpvfG32v5SfX3pO \
    NODE_ENV=production

# Safer: BuildKit secret mount, no value in the file
RUN --mount=type=secret,id=sentry_token cat /run/secrets/sentry_token > /dev/null

CMD ["node", "dist/index.js"]
