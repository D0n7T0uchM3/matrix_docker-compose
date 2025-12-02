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

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    error "Docker Compose is not installed! Please install Docker Compose first."
fi

# Use docker compose or docker-compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

# Check if domain is provided
if [ -z "$DOMAIN" ]; then
    # Try to detect from existing installation
    if [ -f "/opt/matrix/synapse_data/homeserver.yaml" ]; then
        DETECTED_DOMAIN=$(grep "^server_name:" "/opt/matrix/synapse_data/homeserver.yaml" | head -1 | sed 's/server_name:[[:space:]]*"\?\([^"]*\)"\?/\1/' | tr -d '"' | tr -d "'" | xargs | sed 's|^https\?://||')
        if [ -n "$DETECTED_DOMAIN" ]; then
            warning "Domain not specified, using detected domain: $DETECTED_DOMAIN"
            DOMAIN="$DETECTED_DOMAIN"
        fi
    fi
    
    # If still not found, ask user
    if [ -z "$DOMAIN" ]; then
        echo -n "Please enter your Matrix server domain: "
        read DOMAIN
        if [ -z "$DOMAIN" ]; then
            error "Domain cannot be empty!"
        fi
    fi
fi

# Remove http:// or https:// prefix if present
DOMAIN=$(echo "$DOMAIN" | sed 's|^https\?://||')

# Check if email is provided (for SSL certificate)
if [ -z "$EMAIL" ]; then
    warning "Email not specified (needed for SSL certificate)"
    echo -n "Enter email for Let's Encrypt SSL (or press Enter to skip SSL): "
    read EMAIL
    if [ -z "$EMAIL" ]; then
        warning "No email provided - SSL certificate setup will be skipped"
    fi
fi

# Check if domain resolves to current server
CURRENT_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 icanhazip.com 2>/dev/null || echo "unknown")
DOMAIN_IP=""

# Try multiple methods to resolve domain
if command -v dig &> /dev/null; then
    DOMAIN_IP=$(dig +short $DOMAIN 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
elif command -v getent &> /dev/null; then
    DOMAIN_IP=$(getent hosts $DOMAIN 2>/dev/null | awk '{print $1}' | head -1)
elif command -v nslookup &> /dev/null; then
    DOMAIN_IP=$(nslookup $DOMAIN 2>/dev/null | grep -A1 "Name:" | tail -1 | awk '{print $2}')
fi

if [ -n "$CURRENT_IP" ] && [ "$CURRENT_IP" != "unknown" ]; then
    info "Server public IP: $CURRENT_IP"
fi

if [ -n "$DOMAIN_IP" ]; then
    info "Domain $DOMAIN resolves to: $DOMAIN_IP"
    if [ "$CURRENT_IP" != "unknown" ] && [ "$CURRENT_IP" != "$DOMAIN_IP" ]; then
        warning "Domain $DOMAIN resolves to $DOMAIN_IP but server IP is $CURRENT_IP"
        warning "Make sure your DNS A record points to this server's IP: $CURRENT_IP"
        echo ""
        read -p "Continue anyway? (y/N): " continue_anyway
        if [ "$continue_anyway" != "y" ] && [ "$continue_anyway" != "Y" ]; then
            error "Deployment cancelled. Please fix DNS first."
        fi
    fi
fi

log "🚀 Starting Matrix Synapse deployment for domain: $DOMAIN"
info "This script will set up a complete Matrix server with Element Web client"

# Create working directory
log "📁 Creating directory $MATRIX_DIR..."
mkdir -p $MATRIX_DIR
cd $MATRIX_DIR

# Complete cleanup of old data
log "🧹 Performing complete cleanup of old data..."
$DOCKER_COMPOSE down 2>/dev/null || true
docker stop nginx synapse-app synapse-admin element synapse-db 2>/dev/null || true
docker rm -f nginx synapse-app synapse-admin element synapse-db 2>/dev/null || true
docker volume prune -f 2>/dev/null || true
docker network prune -f 2>/dev/null || true
rm -rf pgsql_data synapse_data element_data nginx_data
success "Old data cleaned up"

# Create directory structure
log "📂 Creating directory structure..."
mkdir -p {pgsql_data,synapse_data,element_data,nginx_data/conf.d}
mkdir -p /opt/letsencrypt
success "Directory structure created"

# Create docker-compose.yml (without deprecated version field)
log "🐳 Creating docker-compose.yml configuration..."
tee docker-compose.yml > /dev/null << EOF
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
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/ || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    hostname: nginx
    container_name: nginx
    restart: unless-stopped
    depends_on:
      synapse-app:
        condition: service_healthy
      element:
        condition: service_healthy
    environment:
      TZ: "UTC"
    ports:
      - "80:80"
      - "443:443"
      - "8448:8448"
    volumes:
      - ./nginx_data/conf.d:/etc/nginx/conf.d
      - /opt/letsencrypt:/etc/letsencrypt:ro
    networks:
      - matrix-network

networks:
  matrix-network:
    driver: bridge
EOF
success "Docker Compose configuration created"

# Start PostgreSQL for initialization
log "🐘 Starting PostgreSQL database..."
$DOCKER_COMPOSE up -d synapse-db
log "⏳ Waiting for PostgreSQL initialization..."

# Wait for PostgreSQL to be ready
for i in {1..30}; do
    if $DOCKER_COMPOSE exec -T synapse-db pg_isready -U synapse >/dev/null 2>&1; then
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
TABLE_COUNT=$($DOCKER_COMPOSE exec -T synapse-db psql -U synapse -d synapse -t -c "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ' || echo "0")
if [ "$TABLE_COUNT" != "0" ] && [ "$TABLE_COUNT" != "" ]; then
    warning "Database contains $TABLE_COUNT tables - performing full cleanup"
    $DOCKER_COMPOSE down
    rm -rf pgsql_data/*
    $DOCKER_COMPOSE up -d synapse-db
    sleep 20
fi
success "Database is clean and ready"

# Generate Synapse configuration
log "⚙️ Generating Synapse configuration..."
docker run --rm \
  -v ./synapse_data:/data \
  -e SYNAPSE_SERVER_NAME=$DOMAIN \
  -e SYNAPSE_REPORT_STATS=no \
  matrixdotorg/synapse:latest generate
success "Synapse configuration generated"

# Fix database configuration and add x_forwarded in homeserver.yaml
log "🔧 Configuring PostgreSQL connection and reverse proxy settings..."
python3 << 'PYTHON_EOF'
import re
import sys

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

    # Add x_forwarded: true for reverse proxy support (critical for Jitsi/widgets)
    # Find the listeners section and add x_forwarded after type: http
    if 'x_forwarded:' not in new_content:
        new_content = re.sub(
            r'(type: http)',
            r'\1\n    x_forwarded: true',
            new_content
        )

    # Write back the configuration
    with open(config_file, 'w') as f:
        f.write(new_content)

    print("SUCCESS")
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
PYTHON_EOF

if [ $? -eq 0 ]; then
    success "PostgreSQL and reverse proxy configuration updated"
else
    error "Failed to update configuration"
fi

# Verify x_forwarded is set
if grep -q "x_forwarded: true" synapse_data/homeserver.yaml; then
    success "Reverse proxy headers (x_forwarded) configured"
else
    warning "x_forwarded not found - adding manually..."
    sed -i 's/type: http/type: http\n    x_forwarded: true/' synapse_data/homeserver.yaml
fi

# Create Element Web configuration (will be updated to HTTPS if SSL succeeds)
log "🌐 Creating Element Web configuration..."
tee element_data/config.json > /dev/null << EOF
{
    "default_server_config": {
        "m.homeserver": {
            "base_url": "https://$DOMAIN",
            "server_name": "$DOMAIN"
        }
    },
    "brand": "Element",
    "integrations_ui_url": "https://scalar.vector.im/",
    "integrations_rest_url": "https://scalar.vector.im/api",
    "integrations_widgets_urls": [
        "https://scalar.vector.im/_matrix/integrations/v1"
    ],
    "jitsi": {
        "preferred_domain": "meet.element.io"
    },
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

# Attempt to get SSL certificate BEFORE starting services
SSL_SUCCESS=false
if [ -n "$EMAIL" ]; then
    log "🔒 Attempting to get SSL certificate..."
    
    # Make sure port 80 is free
    $DOCKER_COMPOSE down 2>/dev/null || true
    
    if docker run --rm --name certbot \
      -v "/opt/letsencrypt:/etc/letsencrypt" \
      -p 80:80 \
      certbot/certbot certonly --standalone \
      --non-interactive \
      --agree-tos --email $EMAIL \
      -d $DOMAIN 2>&1; then
        
        # Verify certificate was created
        if [ -f "/opt/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
            SSL_SUCCESS=true
            success "SSL certificate obtained successfully"
        else
            warning "Certbot ran but certificate not found"
        fi
    else
        warning "Failed to obtain SSL certificate"
        info "Common causes: DNS not pointing to this server, port 80 blocked, rate limits"
    fi
else
    warning "No email provided - skipping SSL setup"
fi

# Create Nginx configuration based on SSL status
log "🌐 Creating Nginx configuration..."

if [ "$SSL_SUCCESS" = true ]; then
    # HTTPS configuration
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
    listen 8448 ssl http2;
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
    add_header Content-Security-Policy "frame-ancestors 'self' https://*.element.io https://app.element.io";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Element Web client
    location / {
        proxy_pass http://element:8080;
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
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
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

    # Well-known for Matrix server discovery
    location /.well-known/matrix/server {
        default_type application/json;
        return 200 '{"m.server": "$DOMAIN:443"}';
    }

    location /.well-known/matrix/client {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "https://$DOMAIN"}}';
    }
}
EOF
    PROTO="https"
    success "HTTPS Nginx configuration created"
else
    # HTTP-only configuration
    tee nginx_data/conf.d/matrix.conf > /dev/null << EOF
server {
    listen 80;
    listen 8448;
    server_name $DOMAIN;
    
    # Security headers
    add_header Content-Security-Policy "frame-ancestors 'self' https://*.element.io https://app.element.io";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    
    # Element Web client
    location / {
        proxy_pass http://element:8080;
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
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
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

    # Well-known for Matrix server discovery
    location /.well-known/matrix/server {
        default_type application/json;
        return 200 '{"m.server": "$DOMAIN:8448"}';
    }

    location /.well-known/matrix/client {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "http://$DOMAIN"}}';
    }
}
EOF
    PROTO="http"
    # Update Element config for HTTP
    sed -i 's|https://|http://|g' element_data/config.json
    success "HTTP Nginx configuration created"
fi

# Start all services
log "🚀 Starting all services..."
$DOCKER_COMPOSE up -d
log "⏳ Waiting for all services to start (60 seconds)..."
sleep 60

# Check service status
log "🔍 Checking service status..."
$DOCKER_COMPOSE ps

# Wait for Synapse to be ready
log "⏳ Waiting for Synapse to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8008/_matrix/client/versions >/dev/null 2>&1 || \
       docker exec synapse-app curl -s http://localhost:8008/_matrix/client/versions >/dev/null 2>&1; then
        success "Synapse is ready and responding"
        break
    fi
    if [ $i -eq 30 ]; then
        warning "Synapse may not be ready yet, but continuing..."
        $DOCKER_COMPOSE logs --tail=10 synapse-app
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

# Final system verification
log "🔍 Performing final system verification..."

# Check endpoint availability
if [ "$SSL_SUCCESS" = true ]; then
    if curl -k -s https://localhost/_matrix/client/versions >/dev/null 2>&1; then
        success "HTTPS is working correctly"
    else
        warning "HTTPS endpoint check via localhost failed (may work externally)"
    fi
else
    if curl -s http://localhost/_matrix/client/versions >/dev/null 2>&1; then
        success "HTTP is working correctly"
    else
        warning "HTTP endpoint may not be ready yet"
    fi
fi

# Final container status
log "📊 Final container status:"
$DOCKER_COMPOSE ps

# Display success message and instructions
echo ""
echo "🎉 =============================================="
echo "✅ Matrix Synapse deployment completed successfully!"
echo "=============================================="
echo ""
echo "🌐 Access your Matrix server:"
echo "   Element Web:    $PROTO://$DOMAIN"
echo "   Matrix API:     $PROTO://$DOMAIN/_matrix/client/versions"
if [ "$SSL_SUCCESS" = true ]; then
    echo "   Federation:     https://$DOMAIN:8448"
fi
echo ""
echo "👤 Administrator account:"
echo "   Username:  @$ADMIN_USER:$DOMAIN"
echo "   Password:  $ADMIN_PASS"
echo ""
echo "🔧 System management:"
echo "   Directory:     $MATRIX_DIR"
echo "   Status:        cd $MATRIX_DIR && sudo $DOCKER_COMPOSE ps"
echo "   Logs:          cd $MATRIX_DIR && sudo $DOCKER_COMPOSE logs"
echo "   Restart:       cd $MATRIX_DIR && sudo $DOCKER_COMPOSE restart"
echo "   Stop:          cd $MATRIX_DIR && sudo $DOCKER_COMPOSE down"
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
    echo "   0 2 * * * docker run --rm -v /opt/letsencrypt:/etc/letsencrypt certbot/certbot renew --quiet && cd $MATRIX_DIR && $DOCKER_COMPOSE restart nginx"
else
    echo "⚠️  SSL: Not configured (running on HTTP)"
    echo "🔒 To enable SSL later, run:"
    echo "   cd $MATRIX_DIR"
    echo "   sudo $DOCKER_COMPOSE stop nginx"
    echo "   sudo docker run --rm -v /opt/letsencrypt:/etc/letsencrypt -p 80:80 certbot/certbot certonly --standalone --agree-tos --email YOUR_EMAIL -d $DOMAIN"
    echo "   # Then update nginx config for HTTPS and restart"
fi

echo ""
echo "🛡️  Security recommendations:"
echo "   1. Change the default admin password via Element Web"
echo "   2. Configure firewall: sudo ufw allow 80,443,8448/tcp"
echo "   3. Regular backups of $MATRIX_DIR"
echo "   4. Monitor logs: cd $MATRIX_DIR && sudo $DOCKER_COMPOSE logs -f"
echo ""
echo "✅ Your Matrix Synapse server is ready to use!"
echo "🔗 Documentation: https://matrix.org/docs/"
