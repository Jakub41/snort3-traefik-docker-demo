FROM node:20
WORKDIR /usr/src/app
COPY package*.json app.js ./
RUN npm i 
EXPOSE 3000
CMD ["node", "app.js"]