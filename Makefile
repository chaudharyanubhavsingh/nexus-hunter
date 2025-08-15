# Nexus Hunter - Autonomous Bug Bounty Intelligence Platform
# Makefile for development and deployment

.PHONY: help setup install dev build start stop clean logs test lint format

# Default target
help:
	@echo "🌐 Nexus Hunter - Autonomous Bug Bounty Intelligence Platform"
	@echo ""
	@echo "Available commands:"
	@echo "  setup     - Complete project setup (install dependencies)"
	@echo "  install   - Install all dependencies"
	@echo "  dev       - Start development environment"
	@echo "  build     - Build production images"
	@echo "  start     - Start production environment"
	@echo "  stop      - Stop all services"
	@echo "  restart   - Restart all services"
	@echo "  clean     - Clean up containers and volumes"
	@echo "  logs      - Show logs from all services"
	@echo "  test      - Run tests"
	@echo "  lint      - Run linting"
	@echo "  format    - Format code"
	@echo "  backup    - Backup database"
	@echo "  restore   - Restore database from backup"

# Project setup
setup: install
	@echo "🚀 Setting up Nexus Hunter..."
	@cp .env.example .env
	@echo "📝 Please edit .env file with your configuration"
	@docker-compose up -d postgres redis
	@echo "⏳ Waiting for database to be ready..."
	@sleep 10
	@cd backend && python -m alembic upgrade head
	@echo "✅ Setup complete!"

# Install dependencies
install:
	@echo "📦 Installing dependencies..."
	@cd backend && pip install -e .
	@cd frontend && npm install
	@echo "✅ Dependencies installed!"

# Development environment
dev:
	@echo "🚀 Starting development environment..."
	@docker-compose -f docker-compose.dev.yml up -d postgres redis
	@echo "⏳ Starting services..."
	@trap 'docker-compose -f docker-compose.dev.yml down' EXIT; \
	 (cd backend && uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000) & \
	 (cd frontend && npm run dev) & \
	 wait

# Build production images
build:
	@echo "🔧 Building production images..."
	@docker-compose build --no-cache
	@echo "✅ Images built successfully!"

# Start production environment
start:
	@echo "🚀 Starting Nexus Hunter in production mode..."
	@docker-compose up -d
	@echo "✅ Nexus Hunter is running!"
	@echo "🌐 Frontend: http://localhost:3000"
	@echo "🔧 Backend: http://localhost:8000"
	@echo "📊 API Docs: http://localhost:8000/api/docs"

# Stop all services
stop:
	@echo "🛑 Stopping Nexus Hunter..."
	@docker-compose down
	@echo "✅ All services stopped!"

# Restart services
restart: stop start

# Clean up
clean:
	@echo "🧹 Cleaning up containers and volumes..."
	@docker-compose down -v --remove-orphans
	@docker system prune -f
	@echo "✅ Cleanup complete!"

# Show logs
logs:
	@docker-compose logs -f

# Run tests
test:
	@echo "🧪 Running tests..."
	@cd backend && python -m pytest tests/ -v
	@cd frontend && npm run test
	@echo "✅ Tests completed!"

# Run linting
lint:
	@echo "🔍 Running linting..."
	@cd backend && python -m flake8 backend/ --max-line-length=88
	@cd backend && python -m black --check backend/
	@cd backend && python -m isort --check-only backend/
	@cd frontend && npm run lint
	@echo "✅ Linting completed!"

# Format code
format:
	@echo "✨ Formatting code..."
	@cd backend && python -m black backend/
	@cd backend && python -m isort backend/
	@cd frontend && npm run lint:fix
	@echo "✅ Code formatted!"

# Database backup
backup:
	@echo "💾 Creating database backup..."
	@mkdir -p backups
	@docker-compose exec postgres pg_dump -U nexus nexus_hunter > backups/nexus_backup_$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✅ Database backup created!"

# Database restore
restore:
	@echo "📥 Restoring database from backup..."
	@read -p "Enter backup file path: " backup_file; \
	 docker-compose exec -T postgres psql -U nexus -d nexus_hunter < $$backup_file
	@echo "✅ Database restored!"

# Security scan
security-scan:
	@echo "🔒 Running security scan..."
	@cd backend && python -m safety check
	@cd frontend && npm audit
	@echo "✅ Security scan completed!"

# Generate SSL certificates for development
ssl-certs:
	@echo "🔐 Generating SSL certificates..."
	@mkdir -p docker/nginx/ssl
	@openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout docker/nginx/ssl/nginx-selfsigned.key \
		-out docker/nginx/ssl/nginx-selfsigned.crt \
		-subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
	@echo "✅ SSL certificates generated!"

# Monitor services
monitor:
	@echo "📊 Monitoring services..."
	@watch -n 2 'docker-compose ps && echo "" && docker stats --no-stream' 