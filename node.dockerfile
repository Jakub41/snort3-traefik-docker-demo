FROM node:14
WORKDIR /usr/src/app
COPY package*.json app.js ./
RUN npm i 
EXPOSE 3000
CMD ["node", "app.js"]