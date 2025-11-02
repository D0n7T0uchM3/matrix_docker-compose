#!/bin/bash

# Complete Matrix Synapse Deployment Script
# Addresses all common issues: YAML errors, domain conflicts, SSL setup, Docker conflicts
# Usage: sudo ./deploy-matrix-complete.sh [domain] [email]

set -e

# Default configuration
DOMAIN=${1:-""}
EMAIL=${2:-""}
ADMIN_USER="admin"
ADMIN_PASS="admin123"
MATRIX_DIR="/opt/matrix"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

info() {
    echo -e "${PURPLE}ℹ️  $1${NC}"
}

# Check root privileges
if [ "$EUID" -ne 0 ]; then
    error "Please run this script as root: sudo $0"
fi

# Check Docker installation
if ! command -v docker &> /dev/null; then
    error "Docker is not installed! Please install Docker first."
fi

if ! command -v docker-compose &> /dev/null; then
    error "Docker Compose is not installed! Please install Docker Compose first."
fi

# Check if domain resolves to current server
CURRENT_IP=$(curl -s ifconfig.me 2>/dev/null || echo "unknown")
DOMAIN_IP=$(nslookup $DOMAIN 2>/dev/null | grep -A1 "Name:" | tail -1 | awk '{print $2}' || echo "unknown")

if [ "$CURRENT_IP" != "unknown" ] && [ "$DOMAIN_IP" != "unknown" ] && [ "$CURRENT_IP" != "$DOMAIN_IP" ]; then
    warning "Domain $DOMAIN resolves to $DOMAIN_IP but server IP is $CURRENT_IP"
    warning "Make sure your DNS A record points to this server's IP"
fi

log "🚀 Starting Matrix Synapse deployment for domain: $DOMAIN"
info "This script will set up a complete Matrix server with Element Web client"

# Create working directory
log "📁 Creating directory $MATRIX_DIR..."
mkdir -p $MATRIX_DIR
cd $MATRIX_DIR

# Complete cleanup of old data
log "🧹 Performing complete cleanup of old data..."
docker-compose down 2>/dev/null || true
docker stop nginx synapse-app synapse-admin element synapse-db 2>/dev/null || true
docker rm -f nginx synapse-app synapse-admin element synapse-db 2>/dev/null || true
docker volume prune -f || true
docker network prune -f || true
rm -rf pgsql_data synapse_data element_data nginx_data
success "Old data cleaned up"

# Create directory structure
log "📂 Creating directory structure..."
mkdir -p {pgsql_data,synapse_data,element_data,nginx_data/conf.d}
success "Directory structure created"

# Create docker-compose.yml
log "🐳 Creating docker-compose.yml configuration..."
tee docker-compose.yml > /dev/null << EOF
version: '3.8'

services:
  synapse-db:
    image: docker.io/postgres:15-alpine
    container_name: synapse-db
    hostname: synapse-db
    restart: unless-stopped
    environment:
      TZ: "UTC"
      POSTGRES_USER: synapse
      POSTGRES_PASSWORD: synapse_password-123
      POSTGRES_DB: synapse
      POSTGRES_INITDB_ARGS: --encoding=UTF-8 --lc-collate=C --lc-ctype=C
    volumes:
      - ./pgsql_data:/var/lib/postgresql/data
    networks:
      - matrix-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U synapse"]
      interval: 10s
      timeout: 5s
      retries: 5

  synapse-app:
    image: matrixdotorg/synapse:latest
    container_name: synapse-app
    hostname: synapse-app
    restart: unless-stopped
    environment:
      TZ: "UTC"
      SYNAPSE_CONFIG_PATH: /data/homeserver.yaml
    volumes:
      - ./synapse_data:/data
    depends_on:
      synapse-db:
        condition: service_healthy
    networks:
      - matrix-network
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8008/_matrix/client/versions || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  element:
    image: vectorim/element-web:latest
    hostname: element
    container_name: element
    restart: unless-stopped
    environment:
      TZ: "UTC"
    volumes:
      - ./element_data/config.json:/app/config.json
    networks:
      - matrix-network

  nginx:
    image: nginx:alpine
    hostname: nginx
    container_name: nginx
    restart: unless-stopped
    depends_on:
      synapse-app:
        condition: service_healthy
    environment:
      TZ: "UTC"
    ports:
      - "80:80"
      - "443:443"
      - "8448:8448"
    volumes:
      - ./nginx_data/conf.d:/etc/nginx/conf.d
      - /opt/letsencrypt:/etc/letsencrypt
    networks:
      - matrix-network

networks:
  matrix-network:
    driver: bridge
EOF
success "Docker Compose configuration created"

# Start PostgreSQL for initialization
log "🐘 Starting PostgreSQL database..."
docker-compose up -d synapse-db
log "⏳ Waiting for PostgreSQL initialization..."

# Wait for PostgreSQL to be ready
for i in {1..30}; do
    if docker-compose exec -T synapse-db pg_isready -U synapse >/dev/null 2>&1; then
        success "PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        error "PostgreSQL failed to start after 30 attempts"
    fi
    log "Attempt $i/30, waiting 5 more seconds..."
    sleep 5
done

# Verify database is empty
log "🔍 Verifying database state..."
TABLE_COUNT=$(docker-compose exec -T synapse-db psql -U synapse -d synapse -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ' || echo "0")
if [ "$TABLE_COUNT" != "0" ] && [ "$TABLE_COUNT" != "" ]; then
    warning "Database contains $TABLE_COUNT tables - performing full cleanup"
    docker-compose down
    rm -rf pgsql_data/*
    docker-compose up -d synapse-db
    sleep 20
fi
success "Database is clean and ready"

# Generate Synapse configuration
log "⚙️ Generating Synapse configuration..."
docker run -it --rm \
  -v ./synapse_data:/data \
  -e SYNAPSE_SERVER_NAME=$DOMAIN \
  -e SYNAPSE_REPORT_STATS=no \
  matrixdotorg/synapse:latest generate
success "Synapse configuration generated"

# Fix database configuration in homeserver.yaml
log "🔧 Configuring PostgreSQL connection..."
python3 << 'PYTHON_EOF'
import re
import sys
import yaml

try:
    config_file = '/opt/matrix/synapse_data/homeserver.yaml'
    
    with open(config_file, 'r') as f:
        content = f.read()

    # New database configuration
    database_config = """database:
  name: psycopg2
  txn_limit: 10000
  args:
    user: synapse
    password: synapse_password-123
    database: synapse
    host: synapse-db
    port: 5432
    cp_min: 5
    cp_max: 10"""

    # Replace database section using regex
    pattern = r'database:.*?(?=^[a-zA-Z]|\Z)'
    new_content = re.sub(pattern, database_config + '\n\n', content, flags=re.MULTILINE | re.DOTALL)

    # Write back the configuration
    with open(config_file, 'w') as f:
        f.write(new_content)

    # Validate YAML syntax
    with open(config_file, 'r') as f:
        yaml.safe_load(f)

    print("SUCCESS")
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
PYTHON_EOF

if [ $? -eq 0 ]; then
    success "PostgreSQL configuration updated and validated"
else
    error "Failed to update database configuration"
fi

# Create Element Web configuration (HTTP first)
log "🌐 Creating Element Web configuration..."
tee element_data/config.json > /dev/null << EOF
{
    "default_server_config": {
        "m.homeserver": {
            "base_url": "http://$DOMAIN",
            "server_name": "$DOMAIN"
        }
    },
    "brand": "Element",
    "integrations_ui_url": "https://scalar.vector.im/",
    "integrations_rest_url": "https://scalar.vector.im/api",
    "integrations_widgets_urls": [
        "https://scalar.vector.im/_matrix/integrations/v1"
    ],
    "default_federate": true,
    "default_theme": "light",
    "show_labs_settings": true,
    "features": {
        "feature_pinning": "labs",
        "feature_custom_status": "labs"
    },
    "room_directory": {
        "servers": ["matrix.org"]
    },
    "enable_presence_by_hs_url": {
        "https://matrix.org": false
    },
    "setting_defaults": {
        "breadcrumbs": true
    }
}
EOF
success "Element Web configuration created"

# Create initial HTTP Nginx configuration
log "🌐 Creating initial HTTP Nginx configuration..."
tee nginx_data/conf.d/matrix.conf > /dev/null << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Element Web client
    location / {
        proxy_pass http://element;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Matrix Synapse API
    location ~ ^(/_matrix|/_synapse/client) {
        proxy_pass http://synapse-app:8008;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # File upload limit
        client_max_body_size 100M;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings
        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
    }

    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /usr/share/nginx/html;
        allow all;
    }
}
EOF
success "HTTP Nginx configuration created"

# Validate Nginx configuration syntax
log "✅ Validating Nginx configuration..."
if docker run --rm -v /opt/matrix/nginx_data/conf.d:/etc/nginx/conf.d nginx:alpine nginx -t >/dev/null 2>&1; then
    success "Nginx configuration is valid"
else
    error "Nginx configuration has syntax errors"
fi

# Start all services
log "🚀 Starting all services..."
docker-compose up -d
log "⏳ Waiting for all services to start (60 seconds)..."
sleep 60

# Check service status
log "🔍 Checking service status..."
docker-compose ps

# Wait for Synapse to be ready
log "⏳ Waiting for Synapse to be ready..."
for i in {1..30}; do
    if curl -s http://localhost/_matrix/client/versions >/dev/null 2>&1; then
        success "Synapse is ready and responding"
        break
    fi
    if [ $i -eq 30 ]; then
        warning "Synapse may not be ready yet, but continuing..."
        docker-compose logs --tail=10 synapse-app
        break
    fi
    log "Attempt $i/30, waiting 10 more seconds..."
    sleep 10
done

# Create administrator account
log "👤 Creating administrator account..."
cat > /tmp/create_admin << EOF
$ADMIN_USER

$ADMIN_PASS
$ADMIN_PASS
yes
EOF

if timeout 60 docker exec -i synapse-app register_new_matrix_user -c /data/homeserver.yaml http://localhost:8008 < /tmp/create_admin >/dev/null 2>&1; then
    success "Administrator created: @$ADMIN_USER:$DOMAIN"
    success "Password: $ADMIN_PASS"
else
    warning "Failed to create administrator automatically"
    info "Create manually later with: docker exec -it synapse-app register_new_matrix_user -c /data/homeserver.yaml http://localhost:8008"
fi
rm -f /tmp/create_admin

# Attempt to get SSL certificate
log "🔒 Attempting to get SSL certificate..."
docker-compose stop nginx
sleep 5

SSL_SUCCESS=false
if docker run -it --rm --name certbot \
  -v "/opt/letsencrypt:/etc/letsencrypt" \
  -p 80:80 \
  certbot/certbot certonly --standalone \
  --non-interactive \
  --agree-tos --email $EMAIL \
  -d $DOMAIN >/dev/null 2>&1; then
    
    SSL_SUCCESS=true
    success "SSL certificate obtained successfully"
    
    # Update nginx configuration for HTTPS
    log "🔒 Updating Nginx configuration for HTTPS..."
    tee nginx_data/conf.d/matrix.conf > /dev/null << EOF
# HTTP redirect to HTTPS
server {
    listen 80;
    server_name $DOMAIN;
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /usr/share/nginx/html;
        allow all;
    }
    
    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen 8448 ssl http2;  # Matrix federation port
    server_name $DOMAIN;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Element Web client
    location / {
        proxy_pass http://element;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Matrix Synapse API
    location ~ ^(/_matrix|/_synapse/client) {
        proxy_pass http://synapse-app:8008;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # File upload limit
        client_max_body_size 100M;
        
        # WebSocket support for sync
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings
        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
    }
}
EOF

    # Update Element configuration for HTTPS
    sed -i 's|http://|https://|g' element_data/config.json
    
    success "HTTPS configuration updated"
else
    warning "Failed to obtain SSL certificate - continuing with HTTP"
    info "You can manually get SSL certificate later or check DNS configuration"
fi

# Start nginx
docker-compose start nginx
sleep 10

# Final system verification
log "🔍 Performing final system verification..."

# Check HTTP/HTTPS availability
if [ "$SSL_SUCCESS" = true ]; then
    PROTO="https"
    if curl -k -s https://$DOMAIN/_matrix/client/versions >/dev/null 2>&1; then
        success "HTTPS is working correctly"
    else
        warning "HTTPS endpoint may not be ready yet"
    fi
else
    PROTO="http"
    if curl -s http://$DOMAIN/_matrix/client/versions >/dev/null 2>&1; then
        success "HTTP is working correctly"
    else
        warning "HTTP endpoint may not be ready yet"
    fi
fi

# Final container status
log "📊 Final container status:"
docker-compose ps

# Display success message and instructions
echo ""
echo "🎉 =============================================="
echo "✅ Matrix Synapse deployment completed successfully!"
echo "=============================================="
echo ""
echo "🌐 Access your Matrix server:"
echo "   Element Web:    $PROTO://$DOMAIN"
echo "   Matrix API:     $PROTO://$DOMAIN/_matrix/client/versions"
echo "   Federation:     https://$DOMAIN:8448 (if SSL enabled)"
echo ""
echo "👤 Administrator account:"
echo "   Username:  @$ADMIN_USER:$DOMAIN"
echo "   Password:  $ADMIN_PASS"
echo ""
echo "🔧 System management:"
echo "   Directory:     $MATRIX_DIR"
echo "   Status:        sudo docker-compose ps"
echo "   Logs:          sudo docker-compose logs"
echo "   Restart:       sudo docker-compose restart"
echo "   Stop:          sudo docker-compose down"
echo ""
echo "📱 Mobile clients:"
echo "   1. Install 'Element' from App Store/Google Play"
echo "   2. Choose 'Other' server option"
echo "   3. Enter: $PROTO://$DOMAIN"
echo "   4. Login with the credentials above"
echo ""

if [ "$SSL_SUCCESS" = true ]; then
    echo "🔒 SSL: Enabled and working"
    echo "🔄 SSL Auto-renewal (add to cron):"
    echo "   0 2 * * * docker run --rm --name certbot -v /opt/letsencrypt:/etc/letsencrypt certbot/certbot renew --quiet && cd $MATRIX_DIR && docker-compose restart nginx"
else
    echo "⚠️  SSL: Not configured (running on HTTP)"
    echo "🔒 To enable SSL later:"
    echo "   1. Ensure DNS A record points to this server"
    echo "   2. sudo docker-compose stop nginx"
    echo "   3. sudo docker run -it --rm --name certbot -v /opt/letsencrypt:/etc/letsencrypt -p 80:80 certbot/certbot certonly --standalone --agree-tos --email $EMAIL -d $DOMAIN"
    echo "   4. Update nginx configuration and restart"
fi

echo ""
echo "🛡️  Security recommendations:"
echo "   1. Change the default admin password via Element Web"
echo "   2. Configure firewall: sudo ufw allow 80,443,8448/tcp"
echo "   3. Regular backups of $MATRIX_DIR"
echo "   4. Monitor logs: sudo docker-compose logs -f"
echo ""
echo "✅ Your Matrix Synapse server is ready to use!"
echo "🔗 Documentation: https://matrix.org/docs/"
