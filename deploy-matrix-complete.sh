#!/bin/bash

# Complete Matrix Synapse Deployment Script
# Addresses all common issues: YAML errors, domain conflicts, SSL setup, Docker conflicts
#
# Usage:
#   sudo ./deploy-matrix-complete.sh [domain] [email] [mode]
#
# Positional arguments (all optional - prompted if missing):
#   domain   The public DNS name of the homeserver, e.g. chat.example.com
#   email    Email address used for the Let's Encrypt SSL certificate
#   mode     "full" (Synapse + Element Web) or "api" (Synapse + nginx only)
#
# Environment overrides:
#   INSTALL_ELEMENT=true|false   Skip the interactive mode prompt.
#                                true  -> deploy Element Web at https://DOMAIN
#                                false -> API-only (use Element X, FluffyChat, etc.)

set -e

# Default configuration
DOMAIN=${1:-""}
EMAIL=${2:-""}
MODE_ARG=${3:-""}
ADMIN_USER="admin"
ADMIN_PASS="admin123"
MATRIX_DIR="/opt/matrix"

# INSTALL_ELEMENT: true = include Element Web, false = Matrix API only.
# Resolution order: env var > 3rd CLI arg > interactive prompt.
INSTALL_ELEMENT=${INSTALL_ELEMENT:-""}
if [ -z "$INSTALL_ELEMENT" ] && [ -n "$MODE_ARG" ]; then
    case "$MODE_ARG" in
        full|web|all)    INSTALL_ELEMENT=true ;;
        api|api-only|matrix-only|no-web) INSTALL_ELEMENT=false ;;
        *) ;;  # leave empty - will prompt
    esac
fi

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
    echo -e "${GREEN}[ OK ]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[FAIL]${NC} $1"
    exit 1
}

info() {
    echo -e "${PURPLE}[INFO]${NC} $1"
}

# Domain validation: standard hostname with at least one dot and a valid TLD
validate_domain() {
    local domain="$1"
    [ ${#domain} -le 253 ] && \
    [[ "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]
}

# Email validation: standard RFC-ish email format
validate_email() {
    local email="$1"
    [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
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

# Try to detect domain from existing installation if not provided
if [ -z "$DOMAIN" ] && [ -f "/opt/matrix/synapse_data/homeserver.yaml" ]; then
    DETECTED_DOMAIN=$(grep "^server_name:" "/opt/matrix/synapse_data/homeserver.yaml" | head -1 | sed 's/server_name:[[:space:]]*"\?\([^"]*\)"\?/\1/' | tr -d '"' | tr -d "'" | xargs | sed 's|^https\?://||')
    if [ -n "$DETECTED_DOMAIN" ] && validate_domain "$DETECTED_DOMAIN"; then
        warning "Domain not specified, using detected domain: $DETECTED_DOMAIN"
        DOMAIN="$DETECTED_DOMAIN"
    fi
fi

# Normalize and validate domain (loop until valid input is provided)
DOMAIN=$(echo "$DOMAIN" | sed 's|^https\?://||' | sed 's|/.*$||' | xargs)
while [ -z "$DOMAIN" ] || ! validate_domain "$DOMAIN"; do
    if [ -n "$DOMAIN" ]; then
        warning "Invalid domain format: '$DOMAIN'"
        info "Expected format: matrix.example.com (no protocol, no trailing path)"
    fi
    echo -n "Please enter your Matrix server domain: "
    read DOMAIN
    DOMAIN=$(echo "$DOMAIN" | sed 's|^https\?://||' | sed 's|/.*$||' | xargs)
done
success "Using domain: $DOMAIN"

# Ask for email if not provided (used for Let's Encrypt SSL certificate)
if [ -z "$EMAIL" ]; then
    warning "Email not specified (needed for SSL certificate)"
    echo -n "Enter email for Let's Encrypt SSL (or press Enter to skip SSL): "
    read EMAIL
    EMAIL=$(echo "$EMAIL" | xargs)
fi

# Validate email format if provided (re-prompt until valid or skipped)
while [ -n "$EMAIL" ] && ! validate_email "$EMAIL"; do
    warning "Invalid email format: '$EMAIL'"
    info "Expected format: user@example.com"
    echo -n "Enter a valid email (or press Enter to skip SSL): "
    read EMAIL
    EMAIL=$(echo "$EMAIL" | xargs)
done

if [ -z "$EMAIL" ]; then
    warning "No email provided - SSL certificate setup will be skipped"
else
    success "Using email: $EMAIL"
fi

# Choose installation mode (Element Web vs API-only)
if [ -z "$INSTALL_ELEMENT" ]; then
    echo ""
    info "Installation mode:"
    echo "  1) Full      - Synapse server + Element Web at https://$DOMAIN"
    echo "                 Users can chat directly in the browser."
    echo "  2) API only  - Synapse server only (no in-browser client)"
    echo "                 Connect via Element X / FluffyChat / other Matrix apps,"
    echo "                 or self-host Element Web elsewhere."
    echo ""
    while true; do
        read -p "Choose [1/2] (default 1): " mode_choice
        mode_choice="${mode_choice:-1}"
        case "$mode_choice" in
            1) INSTALL_ELEMENT=true;  break ;;
            2) INSTALL_ELEMENT=false; break ;;
            *) warning "Invalid choice: '$mode_choice'. Enter 1 or 2." ;;
        esac
    done
fi

if [ "$INSTALL_ELEMENT" = "true" ]; then
    success "Mode: Full install (Synapse + Element Web)"
else
    success "Mode: API only (Synapse server, no in-browser client)"
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

log ">> Starting Matrix Synapse deployment for domain: $DOMAIN"
if [ "$INSTALL_ELEMENT" = "true" ]; then
    info "This script will set up a Matrix Synapse server with Element Web client"
else
    info "This script will set up a Matrix Synapse server (API-only, no web client)"
fi

# Create working directory
log ">> Creating directory $MATRIX_DIR..."
mkdir -p $MATRIX_DIR
cd $MATRIX_DIR

# Complete cleanup of old data
log ">> Performing complete cleanup of old data..."
$DOCKER_COMPOSE down 2>/dev/null || true
docker stop nginx synapse-app synapse-admin element synapse-db 2>/dev/null || true
docker rm -f nginx synapse-app synapse-admin element synapse-db 2>/dev/null || true
docker volume prune -f 2>/dev/null || true
docker network prune -f 2>/dev/null || true
rm -rf pgsql_data synapse_data element_data nginx_data
success "Old data cleaned up"

# Create directory structure
log ">> Creating directory structure..."
mkdir -p pgsql_data synapse_data nginx_data/conf.d
if [ "$INSTALL_ELEMENT" = "true" ]; then
    mkdir -p element_data
fi
mkdir -p /opt/letsencrypt
success "Directory structure created"

# Create docker-compose.yml (without deprecated version field)
log ">> Creating docker-compose.yml configuration..."
{
cat << EOF
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
    # Use python (guaranteed in the synapse image) instead of curl.
    healthcheck:
      test: ["CMD-SHELL", "python3 -c \"import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://localhost:8008/_matrix/client/versions',timeout=3).status==200 else 1)\""]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
EOF

if [ "$INSTALL_ELEMENT" = "true" ]; then
cat << EOF

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
    # vectorim/element-web is nginx:alpine based - use wget (in busybox), not curl.
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- --timeout=3 http://localhost:8080/ >/dev/null || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF
fi

cat << EOF

  nginx:
    image: nginx:alpine
    hostname: nginx
    container_name: nginx
    restart: unless-stopped
    depends_on:
      synapse-app:
        condition: service_healthy
EOF

if [ "$INSTALL_ELEMENT" = "true" ]; then
cat << EOF
      element:
        condition: service_healthy
EOF
fi

cat << EOF
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
} > docker-compose.yml
success "Docker Compose configuration created"

# Start PostgreSQL for initialization
log ">> Starting PostgreSQL database..."
$DOCKER_COMPOSE up -d synapse-db
log ">> Waiting for PostgreSQL initialization..."

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
log ">> Verifying database state..."
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
log ">> Generating Synapse configuration..."
docker run --rm \
  -v ./synapse_data:/data \
  -e SYNAPSE_SERVER_NAME=$DOMAIN \
  -e SYNAPSE_REPORT_STATS=no \
  matrixdotorg/synapse:latest generate
success "Synapse configuration generated"

# Fix database configuration and add x_forwarded in homeserver.yaml
log ">> Configuring PostgreSQL connection and reverse proxy settings..."
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

# Create Element Web configuration (only when Element is being deployed).
# Will be updated to HTTP if SSL setup later fails.
if [ "$INSTALL_ELEMENT" = "true" ]; then
log ">> Creating Element Web configuration..."
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
else
    info "Skipping Element Web config (API-only mode)"
fi

# Attempt to get SSL certificate BEFORE starting services
SSL_SUCCESS=false
if [ -n "$EMAIL" ]; then
    log ">> Attempting to get SSL certificate..."
    
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
log ">> Creating Nginx configuration..."

# Pick what serves the root path '/'. If Element Web is installed we proxy to
# it; otherwise we serve a small static landing page that points users at
# mobile / desktop Matrix clients.
if [ "$INSTALL_ELEMENT" = "true" ]; then
    NGINX_ROOT_LOCATION="    # Element Web (catch-all, MUST be last)
    location / {
        proxy_pass http://element:8080;
        proxy_redirect off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }"
else
    NGINX_ROOT_LOCATION="    # API-only mode: serve a small landing page at '/' and 404 for everything else.
    location = / {
        default_type text/html;
        return 200 \"<!doctype html><html lang=\\\"en\\\"><head><meta charset=\\\"utf-8\\\"><title>Matrix homeserver - $DOMAIN</title><style>body{font-family:system-ui,-apple-system,sans-serif;max-width:560px;margin:3em auto;padding:0 1em;color:#222;line-height:1.5}h1{font-size:1.3em}code{background:#f1f1f1;padding:.15em .4em;border-radius:3px}ul{padding-left:1.2em}a{color:#0a64bc}</style></head><body><h1>Matrix homeserver</h1><p>This server hosts the Matrix client/server API at <code>/_matrix/</code>.</p><p>No in-browser web client is installed on this host. Connect with a Matrix app:</p><ul><li><a href=\\\"https://element.io/download\\\">Element / Element X</a></li><li><a href=\\\"https://fluffychat.im/\\\">FluffyChat</a></li><li><a href=\\\"https://matrix.org/clients/\\\">More Matrix clients</a></li></ul><p>Homeserver: <code>$DOMAIN</code></p></body></html>\";
    }
    location / {
        return 404 \"Not Found. This server only exposes the Matrix API. Use a Matrix client and connect to $DOMAIN.\\n\";
    }"
fi

if [ "$SSL_SUCCESS" = true ]; then
    # HTTPS configuration
    tee nginx_data/conf.d/matrix.conf > /dev/null << EOF
# HTTP -> HTTPS redirect
server {
    listen 80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ {
        root /usr/share/nginx/html;
        allow all;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

# HTTPS server (client + federation)
server {
    listen 443 ssl;
    listen 8448 ssl;
    http2 on;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "frame-ancestors 'self' https://*.element.io https://app.element.io";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    client_max_body_size 100M;

    # Matrix client/server API.
    # '^~' guarantees this prefix wins over any regex location and over the
    # catch-all '/' (which proxies to Element). This is the single most
    # common cause of "cannot reach the server" in Element Web.
    location ^~ /_matrix/ {
        proxy_pass http://synapse-app:8008;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;

        # CORS: same-origin doesn't strictly need this, but it makes the API
        # usable from third-party clients hosted elsewhere too.
        add_header Access-Control-Allow-Origin "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization" always;
        if (\$request_method = OPTIONS) {
            return 204;
        }
    }

    location ^~ /_synapse/ {
        proxy_pass http://synapse-app:8008;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Matrix server discovery (federation + client)
    location = /.well-known/matrix/server {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.server": "$DOMAIN:443"}';
    }

    location = /.well-known/matrix/client {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "https://$DOMAIN"}}';
    }

$NGINX_ROOT_LOCATION
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

    add_header Content-Security-Policy "frame-ancestors 'self' https://*.element.io https://app.element.io";
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    client_max_body_size 100M;

    # See HTTPS block above for why we use '^~' here.
    location ^~ /_matrix/ {
        proxy_pass http://synapse-app:8008;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_connect_timeout 600s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;

        add_header Access-Control-Allow-Origin "*" always;
        add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
        add_header Access-Control-Allow-Headers "Origin, X-Requested-With, Content-Type, Accept, Authorization" always;
        if (\$request_method = OPTIONS) {
            return 204;
        }
    }

    location ^~ /_synapse/ {
        proxy_pass http://synapse-app:8008;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /.well-known/acme-challenge/ {
        root /usr/share/nginx/html;
        allow all;
    }

    location = /.well-known/matrix/server {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.server": "$DOMAIN:8448"}';
    }

    location = /.well-known/matrix/client {
        default_type application/json;
        add_header Access-Control-Allow-Origin *;
        return 200 '{"m.homeserver": {"base_url": "http://$DOMAIN"}}';
    }

$NGINX_ROOT_LOCATION
}
EOF
    PROTO="http"
    # Update Element config for HTTP (only when Element was deployed)
    if [ "$INSTALL_ELEMENT" = "true" ] && [ -f element_data/config.json ]; then
        sed -i 's|https://|http://|g' element_data/config.json
    fi
    success "HTTP Nginx configuration created"
fi

# Start all services
log ">> Starting all services..."
$DOCKER_COMPOSE up -d
log ">> Waiting for all services to start (60 seconds)..."
sleep 60

# Check service status
log ">> Checking service status..."
$DOCKER_COMPOSE ps

# Wait for Synapse to be ready
log ">> Waiting for Synapse to be ready..."
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
log ">> Creating administrator account..."
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
log ">> Performing final system verification..."

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
log ">> Final container status:"
$DOCKER_COMPOSE ps

# Display success message and instructions
echo ""
echo "+=============================================================+"
echo "|                                                             |"
echo "|     Matrix Synapse deployment completed successfully!       |"
echo "|                                                             |"
echo "+=============================================================+"
echo ""
echo "[ Access your Matrix server ]"
if [ "$INSTALL_ELEMENT" = "true" ]; then
    echo "   Element Web:    $PROTO://$DOMAIN"
fi
echo "   Matrix API:     $PROTO://$DOMAIN/_matrix/client/versions"
if [ "$SSL_SUCCESS" = true ]; then
    echo "   Federation:     https://$DOMAIN:8448"
fi
if [ "$INSTALL_ELEMENT" != "true" ]; then
    echo "   Mode:           API only (no in-browser client)"
fi
echo ""
echo "[ Administrator account ]"
echo "   Username:  @$ADMIN_USER:$DOMAIN"
echo "   Password:  $ADMIN_PASS"
echo ""
echo "[ System management ]"
echo "   Directory:     $MATRIX_DIR"
echo "   Status:        cd $MATRIX_DIR && sudo $DOCKER_COMPOSE ps"
echo "   Logs:          cd $MATRIX_DIR && sudo $DOCKER_COMPOSE logs"
echo "   Restart:       cd $MATRIX_DIR && sudo $DOCKER_COMPOSE restart"
echo "   Stop:          cd $MATRIX_DIR && sudo $DOCKER_COMPOSE down"
echo ""
echo "[ Mobile clients ]"
echo "   1. Install 'Element' from App Store/Google Play"
echo "   2. Choose 'Other' server option"
echo "   3. Enter: $PROTO://$DOMAIN"
echo "   4. Login with the credentials above"
echo ""

if [ "$SSL_SUCCESS" = true ]; then
    echo "[ SSL ] Enabled and working"
    echo "[ SSL ] Auto-renewal (add to cron):"
    echo "   0 2 * * * docker run --rm -v /opt/letsencrypt:/etc/letsencrypt certbot/certbot renew --quiet && cd $MATRIX_DIR && $DOCKER_COMPOSE restart nginx"
else
    echo "[WARN] SSL: Not configured (running on HTTP)"
    echo "[ SSL ] To enable SSL later, run:"
    echo "   cd $MATRIX_DIR"
    echo "   sudo $DOCKER_COMPOSE stop nginx"
    echo "   sudo docker run --rm -v /opt/letsencrypt:/etc/letsencrypt -p 80:80 certbot/certbot certonly --standalone --agree-tos --email YOUR_EMAIL -d $DOMAIN"
    echo "   # Then update nginx config for HTTPS and restart"
fi

echo ""
echo "[ Security recommendations ]"
if [ "$INSTALL_ELEMENT" = "true" ]; then
    echo "   1. Change the default admin password via Element Web"
else
    echo "   1. Change the default admin password from your Matrix client"
fi
echo "   2. Configure firewall: sudo ufw allow 80,443,8448/tcp"
echo "   3. Regular backups of $MATRIX_DIR"
echo "   4. Monitor logs: cd $MATRIX_DIR && sudo $DOCKER_COMPOSE logs -f"
echo ""
echo "[ OK ] Your Matrix Synapse server is ready to use!"
echo "[DOCS] https://matrix.org/docs/"
