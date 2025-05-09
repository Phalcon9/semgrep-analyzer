# Use Node.js base image
FROM node:16

# Install Python and pip
RUN apt-get update && apt-get install -y python3 python3-pip

# Install Semgrep
RUN pip3 install semgrep

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the TypeScript code
RUN npm run build

# Expose port (if necessary)
EXPOSE 3000

# Start the compiled JavaScript app
CMD ["npm", "start"]
