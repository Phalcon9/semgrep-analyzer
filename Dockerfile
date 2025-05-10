# Dockerfile optimized for Render deployment
FROM node:16-slim

# Install Python, pip and other dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    ca-certificates \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep with specific version to ensure compatibility
RUN pip3 install semgrep==1.29.0

# Create app directory
WORKDIR /usr/src/app

# Copy package files first (for better caching)
COPY package*.json ./
RUN npm install
RUN npm install -g typescript

# Create log directory with permissions
RUN mkdir -p /usr/src/app/logs && chmod 777 /usr/src/app/logs

# Copy the semgrep configuration first (separate step for caching)
COPY .semgrep-custom.yml /usr/src/app/.semgrep-custom.yml

# Copy the rest of the application code
COPY . .

# Build the TypeScript code
RUN npm run build

# Create temp directory with proper permissions
RUN mkdir -p /usr/src/app/dist/temp && chmod 777 /usr/src/app/dist/temp

# Expose port
EXPOSE 3000

# Set environment variables for Semgrep
ENV SEMGREP_TIMEOUT=0
ENV SEMGREP_MAX_MEMORY=0
ENV SEMGREP_ENABLE_VERSION_CHECK=0

# Start the compiled JavaScript app
CMD ["node", "dist/index.js"]