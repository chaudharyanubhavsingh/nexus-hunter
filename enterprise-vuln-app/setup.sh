#!/bin/bash

# VulnCorp Enterprise Setup Script
# Comprehensive vulnerable application setup for security testing

set -e  # Exit on any error

echo "🏢 VulnCorp Enterprise - Comprehensive Vulnerable Application Setup"
echo "================================================================="
echo ""
echo "⚠️  WARNING: This application contains intentional vulnerabilities!"
echo "    Only use in controlled testing environments."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "🔍 Checking Prerequisites..."
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 18+ first."
        exit 1
    fi
    
    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        print_error "Node.js version 18 or higher is required. Current version: $(node -v)"
        exit 1
    fi
    print_status "Node.js version: $(node -v) ✓"
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed. Please install npm first."
        exit 1
    fi
    print_status "npm version: $(npm -v) ✓"
    
    # Check Docker (optional but recommended)
    if command -v docker &> /dev/null; then
        print_status "Docker version: $(docker -v) ✓"
        DOCKER_AVAILABLE=true
    else
        print_warning "Docker not found. Database services will need to be installed manually."
        DOCKER_AVAILABLE=false
    fi
    
    # Check Docker Compose (optional but recommended)
    if command -v docker-compose &> /dev/null; then
        print_status "Docker Compose version: $(docker-compose -v) ✓"
        COMPOSE_AVAILABLE=true
    else
        print_warning "Docker Compose not found. Will use 'docker compose' instead."
        COMPOSE_AVAILABLE=false
    fi
}

# Setup environment variables
setup_environment() {
    print_header "🌍 Setting up Environment..."
    
    if [ ! -f .env ]; then
        print_status "Creating .env file from template..."
        cat > .env << EOL
# VulnCorp Enterprise Environment Configuration
# WARNING: These are intentionally weak settings for testing!

# Environment
NODE_ENV=development

# Database Configuration (MySQL)
DB_HOST=localhost
DB_PORT=3306
DB_NAME=vulncorp_enterprise
DB_USER=vulnuser
DB_PASS=weakpassword

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASS=

# MongoDB Configuration
MONGODB_HOST=localhost
MONGODB_PORT=27017
MONGODB_DB=vulncorp_nosql
MONGODB_USER=
MONGODB_PASS=

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=pguser
POSTGRES_PASS=weakpgpass
POSTGRES_DB=vulncorp_pg

# Elasticsearch Configuration
ELASTICSEARCH_HOST=localhost
ELASTICSEARCH_PORT=9200

# LDAP Configuration
LDAP_HOST=localhost
LDAP_PORT=389
LDAP_BIND_DN=cn=admin,dc=vulncorp,dc=local
LDAP_BIND_PASS=ldappassword

# Security Configuration (INTENTIONALLY WEAK)
JWT_SECRET=super_weak_jwt_secret_123
SESSION_SECRET=vulnerable_session_secret
ADMIN_EMAIL=admin@vulncorp.local
ADMIN_PASSWORD=admin123

# API Configuration
PORT=3001
HOST=0.0.0.0

# File Upload Configuration
UPLOAD_PATH=./uploads
MAX_FILE_SIZE=104857600
ALLOWED_TYPES=*/*
ALLOWED_EXTENSIONS=*

# Logging Configuration
LOG_LEVEL=debug
LOG_SENSITIVE_DATA=true
LOG_FULL_REQUESTS=true
EOL
        print_status ".env file created with default vulnerable settings ✓"
    else
        print_status ".env file already exists ✓"
    fi
}

# Install dependencies
install_dependencies() {
    print_header "📦 Installing Dependencies..."
    
    # Root dependencies
    print_status "Installing root workspace dependencies..."
    npm install
    
    # Backend dependencies
    print_status "Installing backend dependencies..."
    cd backend && npm install && cd ..
    
    # Frontend dependencies (if exists)
    if [ -d "frontend" ]; then
        print_status "Installing frontend dependencies..."
        cd frontend && npm install && cd ..
    fi
    
    # WebSocket service dependencies (if exists)
    if [ -d "websocket" ]; then
        print_status "Installing WebSocket service dependencies..."
        cd websocket && npm install && cd ..
    fi
    
    print_status "All dependencies installed ✓"
}

# Setup databases
setup_databases() {
    print_header "🗄️ Setting up Databases..."
    
    if [ "$DOCKER_AVAILABLE" = true ]; then
        print_status "Starting database services with Docker..."
        
        # Start only database services
        if [ "$COMPOSE_AVAILABLE" = true ]; then
            docker-compose up -d mysql redis mongodb postgres elasticsearch openldap
        else
            docker compose up -d mysql redis mongodb postgres elasticsearch openldap
        fi
        
        print_status "Waiting for databases to be ready..."
        sleep 30
        
        # Check if databases are ready
        print_status "Verifying database connections..."
        
        # Test MySQL connection
        if docker exec vulncorp-mysql mysql -u vulnuser -pweakpassword -e "SELECT 1" &> /dev/null; then
            print_status "MySQL connection verified ✓"
        else
            print_warning "MySQL connection failed. May need more time to start."
        fi
        
        # Test Redis connection
        if docker exec vulncorp-redis redis-cli ping &> /dev/null; then
            print_status "Redis connection verified ✓"
        else
            print_warning "Redis connection failed. May need more time to start."
        fi
        
    else
        print_warning "Docker not available. Please install and configure databases manually:"
        echo "  - MySQL 8.0 (Host: localhost:3306, DB: vulncorp_enterprise)"
        echo "  - Redis (Host: localhost:6379)"
        echo "  - MongoDB (Host: localhost:27017, DB: vulncorp_nosql)"
        echo "  - PostgreSQL (Host: localhost:5432, DB: vulncorp_pg)"
        echo "  - Elasticsearch (Host: localhost:9200)"
        echo "  - OpenLDAP (Host: localhost:389)"
    fi
}

# Initialize databases with schema and data
initialize_data() {
    print_header "📊 Initializing Database Schemas and Demo Data..."
    
    # Wait for databases to be fully ready
    print_status "Waiting for databases to be fully initialized..."
    sleep 10
    
    # Run database initialization scripts
    if [ -f "backend/src/scripts/setup-database.ts" ]; then
        print_status "Running database setup script..."
        cd backend
        npx ts-node src/scripts/setup-database.ts || print_warning "Database setup script failed"
        cd ..
    fi
    
    # Populate with demo data
    if [ -f "backend/src/scripts/seed-data.ts" ]; then
        print_status "Seeding demo data..."
        cd backend
        npx ts-node src/scripts/seed-data.ts || print_warning "Data seeding script failed"
        cd ..
    fi
    
    print_status "Database initialization complete ✓"
}

# Create necessary directories
create_directories() {
    print_header "📁 Creating Application Directories..."
    
    # Create upload directories
    mkdir -p uploads/avatars
    mkdir -p uploads/documents
    mkdir -p uploads/temp
    chmod 755 uploads
    chmod 755 uploads/*
    
    # Create log directories
    mkdir -p logs
    chmod 755 logs
    
    # Create backend build directory
    mkdir -p backend/dist
    
    print_status "Directories created ✓"
}

# Build applications
build_applications() {
    print_header "🔨 Building Applications..."
    
    # Build backend
    print_status "Building backend TypeScript..."
    cd backend
    npm run build || print_warning "Backend build failed (this is normal if scripts are missing)"
    cd ..
    
    # Build frontend (if exists)
    if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
        print_status "Building frontend application..."
        cd frontend
        npm run build || print_warning "Frontend build failed"
        cd ..
    fi
    
    print_status "Build process complete ✓"
}

# Print setup completion and instructions
print_completion() {
    print_header "🎉 Setup Complete!"
    echo ""
    echo "VulnCorp Enterprise has been successfully set up."
    echo ""
    echo -e "${GREEN}🚀 To start the application:${NC}"
    echo "   npm run dev              # Start all services in development mode"
    echo "   npm run dev:backend      # Start only backend API"
    echo "   npm run dev:frontend     # Start only frontend (if available)"
    echo ""
    echo -e "${BLUE}📊 Application URLs:${NC}"
    echo "   Backend API:  http://localhost:3001"
    echo "   Frontend:     http://localhost:3000 (if available)"
    echo "   WebSocket:    ws://localhost:3002"
    echo ""
    echo -e "${YELLOW}🚨 Vulnerability Testing Endpoints:${NC}"
    echo "   SQL Injection:      http://localhost:3001/api/vulnerable/sql"
    echo "   XSS:               http://localhost:3001/api/vulnerable/xss"
    echo "   Command Injection: http://localhost:3001/api/vulnerable/rce"
    echo "   LFI:               http://localhost:3001/api/vulnerable/lfi"
    echo "   SSRF:              http://localhost:3001/api/vulnerable/ssrf"
    echo "   XXE:               http://localhost:3001/api/vulnerable/xxe"
    echo "   Template Injection: http://localhost:3001/api/vulnerable/template"
    echo "   JWT Vulnerabilities: http://localhost:3001/api/vulnerable/jwt"
    echo "   Business Logic:    http://localhost:3001/api/vulnerable/business"
    echo "   NoSQL Injection:   http://localhost:3001/api/vulnerable/nosql"
    echo ""
    echo -e "${RED}⚠️  SECURITY WARNING:${NC}"
    echo "   This application contains INTENTIONAL security vulnerabilities!"
    echo "   - Only use in isolated, controlled environments"
    echo "   - Never deploy to production or public networks"
    echo "   - Use for security testing and education only"
    echo ""
    echo -e "${GREEN}🎯 Ready for Nexus Hunter testing!${NC}"
    echo "   You can now run your Nexus Hunter security scans against this application."
}

# Main setup process
main() {
    echo "Starting VulnCorp Enterprise setup process..."
    echo ""
    
    check_prerequisites
    setup_environment
    create_directories
    install_dependencies
    setup_databases
    initialize_data
    build_applications
    print_completion
    
    echo ""
    echo -e "${GREEN}Setup completed successfully! 🎉${NC}"
}

# Handle script interruption
trap 'echo -e "\n${RED}Setup interrupted by user.${NC}"; exit 1' INT

# Run main setup
main "$@"

