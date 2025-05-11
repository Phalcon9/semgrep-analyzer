FROM python:3.11-slim

# Install system dependencies and cleanup in one layer
RUN apt-get update && \
    apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install semgrep in virtual environment
RUN pip install --no-cache-dir semgrep==1.121.0

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install TypeScript and other dev dependencies needed for build
RUN npm install typescript @types/node -g && \
    npm ci

# Copy source code and configuration
COPY . .

# Build TypeScript
RUN npm run build

# Create temp directory with proper permissions
RUN mkdir -p dist/temp && \
    chmod -R 777 dist/temp

# Ensure semgrep config is copied and has correct permissions
COPY .semgrep-custom.yml /usr/src/app/.semgrep-custom.yml
RUN chmod 644 /usr/src/app/.semgrep-custom.yml

# Clean up dev dependencies if needed
RUN npm prune --production

# Set production environment
ENV NODE_ENV=production

# Set the command to run the application
CMD ["npm", "start"]