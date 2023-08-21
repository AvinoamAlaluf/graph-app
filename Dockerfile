# Use the official Node.js image as the base image
FROM node:14

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to the container
COPY package*.json ./

# Install project dependencies
RUN npm install

# Copy all files from your current directory to the container
COPY . .

# Build the Vue.js client
RUN cd client && npm install && npm run build

# Clean public and move vue client to it 
RUN rm -r public && mkdir public

# Move vue client to it 
RUN cd client && mv dist/* ../public/

# Expose the port your Node.js server will listen on
EXPOSE 3000

# Command to start your Node.js server
CMD [ "node", "index.js" ]