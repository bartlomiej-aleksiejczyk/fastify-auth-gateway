FROM node:22-alpine AS build

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production

COPY . .

ENV PORT=3000

FROM node:22-alpine

WORKDIR /app

COPY --from=build /app /app

EXPOSE 3000

ENV NODE_ENV=production

CMD ["npm", "run", "start"]
