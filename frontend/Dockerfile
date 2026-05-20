FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

# F-006 FIX: Run as non-root user
RUN adduser -D appuser
USER appuser

CMD ["npm", "run", "dev", "--", "--host"]
