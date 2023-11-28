FROM node:16.13.1-alpine
RUN apk --no-cache add dumb-init
RUN mkdir -p /home/node/app && chown node:node /home/node/app
WORKDIR /home/node/app
USER node
RUN mkdir tmp

COPY --chown=node:node ./package*.json ./
RUN npm ci
COPY --chown=node:node . .
RUN node ace build --production

EXPOSE 3333
CMD [ "dumb-init", "node", "build/server.js" ]
