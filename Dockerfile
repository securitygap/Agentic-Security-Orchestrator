# Multi-stage build for React/Vite + Express Full-Stack App
FROM node:18-alpine AS builder

WORKDIR /app

# Copy configuration files
COPY package*.json ./

# Install dependencies (required to build client & compile server.ts)
RUN npm ci

# Copy application source files
COPY . .

# Compile client frontend and bundle Express server.ts via esbuild
RUN npm run build

# --- Production Runtime Image ---
FROM node:18-alpine AS runner

WORKDIR /app

# Set default env
ENV NODE_ENV=production
ENV PORT=3000

# Copy package configurations and install only production dependencies
COPY package*.json ./
RUN npm ci --omit=dev

# Copy compiled files from builder stage
COPY --from=builder /app/dist ./dist

# Expose port 3000
EXPOSE 3000

# Start the Node.js production server
CMD ["node", "dist/server.cjs"]
