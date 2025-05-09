# Use Node.js base image
FROM node:16

# Install Python and pip
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip3 install semgrep

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies and TypeScript globally
COPY package*.json ./
RUN npm install
RUN npm install -g typescript

# Copy Semgrep configuration
COPY .semgrep-custom.yml /usr/src/app/.semgrep-custom.yml

# Copy the rest of the application code
COPY . .

# Build the TypeScript code
RUN npm run build

# Create temp directory
RUN mkdir -p /usr/src/app/dist/temp

# Expose port (if necessary)
EXPOSE 3000

# Start the compiled JavaScript app
CMD ["npm", "start"]
