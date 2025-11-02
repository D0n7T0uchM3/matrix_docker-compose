# 🚀 Matrix Synapse - Complete Deployment Solution

> Matrix Synapse deployment scripts

[![Matrix](https://img.shields.io/badge/Matrix-Server-green.svg)](https://matrix.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docs.docker.com/compose/)

## 🎯 What's Included

This repository provides a complete, battle-tested solution for deploying Matrix Synapse:

- ✅ **Matrix Synapse** - Main homeserver
- ✅ **Element Web** - Modern web client  
- ✅ **PostgreSQL** - Reliable database backend
- ✅ **Nginx** - Web proxy with SSL/TLS
- ✅ **Let's Encrypt** - Automatic SSL certificates
- ✅ **Admin Tools** - Comprehensive management utilities
- ✅ **Health Monitoring** - System status and diagnostics
- ✅ **Backup/Restore** - Data protection utilities

## 🌟 Key Features

### 🛠️ **Problem-Free Deployment**
- Handles all common YAML configuration errors
- Resolves Docker Compose volume conflicts
- Fixes domain migration issues
- Automatic database initialization
- Smart SSL certificate management

### 🔧 **Production Ready**
- Health checks and monitoring
- Automatic service recovery
- Security headers and best practices
- Comprehensive logging
- Performance optimizations

### 📱 **Client Support**
- Web client (Element Web)
- Mobile apps (iOS/Android)
- Desktop clients
- Third-party clients via standard Matrix API

## 📋 Prerequisites

### System Requirements
- **Operating System**: Ubuntu 20.04+ / Debian 11+
- **Memory**: Minimum 2GB RAM (4GB recommended)
- **Storage**: 20GB+ available disk space
- **CPU**: 2+ cores recommended

### Network Requirements
- **Domain**: Registered domain pointing to your server
- **Ports**: 80, 443, 8448 accessible from internet
- **DNS**: A record configured for your domain

### Software Dependencies
- **Docker**: Version 20.10+
- **Docker Compose**: Version 1.29+
- **Root access** to the server

## ⚡ Quick Start

### 1. Install Docker (if not already installed)

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

### 2. Deploy Matrix Synapse

```bash
# Download the deployment script
wget https://raw.githubusercontent.com/D0n7T0uchM3/matrix_docker-compose/refs/heads/main/deploy-matrix-complete.sh
chmod +x deploy-matrix-complete.sh

# Run deployment (replace with your domain and email)
sudo ./deploy-matrix-complete.sh your-domain.com your-email@example.com
```

### 3. Access Your Matrix Server

After deployment (5-10 minutes), you'll have:

- **Web Client**: `https://your-domain.com`
- **Admin Login**: `@admin:your-domain.com`
- **Default Password**: `admin123`
- **Admin Panel**: Built into Element Web

## 🛠️ Management Tools

### Download Management Script

```bash
wget https://raw.githubusercontent.com/D0n7T0uchM3/matrix_docker-compose/refs/heads/main/matrix-manager.sh
chmod +x matrix-manager.sh
```

### User Management

```bash
# Create a regular user
sudo ./matrix-manager.sh user create alice password123 no

# Create an administrator
sudo ./matrix-manager.sh user create bob secretpass yes

# List all users
sudo ./matrix-manager.sh user list

# Reset user password
sudo ./matrix-manager.sh user reset-password alice
```

### System Management

```bash
# Check system status
sudo ./matrix-manager.sh system status

# Restart services
sudo ./matrix-manager.sh system restart

# Update to latest versions
sudo ./matrix-manager.sh system update

# Stop all services
sudo ./matrix-manager.sh system stop
```

### Backup & Restore

```bash
# Create backup
sudo ./matrix-manager.sh backup create

# Restore from backup
sudo ./matrix-manager.sh backup restore /opt/matrix-backup-20241102-123456.tar.gz
```

### SSL Management

```bash
# Setup SSL certificate
sudo ./matrix-manager.sh ssl setup your-email@example.com

# Renew SSL certificate
sudo ./matrix-manager.sh ssl renew
```

### Monitoring & Logs

```bash
# View system health
sudo ./matrix-manager.sh health

# View recent logs
sudo ./matrix-manager.sh logs view synapse-app 100

# Follow live logs
sudo ./matrix-manager.sh logs follow nginx
```

## 🔧 Advanced Configuration

### Custom Domain Configuration

To deploy with a custom domain, simply specify it during deployment:

```bash
sudo ./deploy-matrix-complete.sh matrix.yourcompany.com admin@yourcompany.com
```

### Environment Customization

Edit the deployment script variables at the top:

```bash
# Custom configuration
DOMAIN="your-domain.com"
EMAIL="your-email@domain.com"
ADMIN_USER="administrator"
ADMIN_PASS="secure-password-123"
MATRIX_DIR="/opt/matrix"
```

### PostgreSQL Tuning

For high-load instances, modify `docker-compose.yml`:

```yaml
synapse-db:
  environment:
    POSTGRES_SHARED_PRELOAD_LIBRARIES: pg_stat_statements
    POSTGRES_MAX_CONNECTIONS: 200
    POSTGRES_SHARED_BUFFERS: 256MB
    POSTGRES_EFFECTIVE_CACHE_SIZE: 1GB
```

### Synapse Performance Tuning

Edit `synapse_data/homeserver.yaml`:

```yaml
# Connection pools
database:
  args:
    cp_min: 10
    cp_max: 20

# Caching
caches:
  global_factor: 2.0

# Rate limiting
rc_message:
  per_second: 10
  burst_count: 50
```

## 🚨 Troubleshooting

### Common Issues and Solutions

#### 1. **Domain doesn't resolve to server**
```bash
# Check DNS resolution
nslookup your-domain.com

# Verify server IP
curl -s ifconfig.me

# Solution: Update DNS A record to point to server IP
```

#### 2. **SSL certificate fails**
```bash
# Check domain accessibility
curl -I http://your-domain.com

# Manual SSL certificate
sudo docker-compose stop nginx
sudo docker run -it --rm --name certbot \
  -v "/opt/letsencrypt:/etc/letsencrypt" \
  -p 80:80 \
  certbot/certbot certonly --standalone \
  --agree-tos --email your-email@domain.com \
  -d your-domain.com
```

#### 3. **Container keeps restarting**
```bash
# Check specific service logs
sudo docker-compose logs synapse-app
sudo docker-compose logs nginx

# Common fix: regenerate configuration
sudo ./deploy-matrix-complete.sh your-domain.com your-email@domain.com
```

#### 4. **Database connection issues**
```bash
# Check database status
sudo docker-compose exec synapse-db pg_isready -U synapse

# Reset database (WARNING: loses all data)
sudo docker-compose down
sudo rm -rf /opt/matrix/pgsql_data/*
sudo docker-compose up -d synapse-db
```

#### 5. **Performance issues**
```bash
# Check resource usage
sudo docker stats

# Check disk space
df -h /opt/matrix

# Monitor active connections
sudo docker-compose exec synapse-db psql -U synapse -c "SELECT count(*) FROM pg_stat_activity;"
```

### Log Analysis

#### Key log files to monitor:
```bash
# Synapse application logs
sudo docker-compose logs synapse-app | grep ERROR

# Nginx access logs
sudo docker-compose logs nginx | grep -E "40[0-9]|50[0-9]"

# Database logs
sudo docker-compose logs synapse-db | grep ERROR
```

## 📱 Client Setup

### Web Client (Element Web)
1. Navigate to `https://your-domain.com`
2. Login with `@admin:your-domain.com` / `admin123`
3. Change password in Settings → Security & Privacy

### Mobile Clients

#### iOS (Element)
1. Download Element from App Store
2. Choose "Other" server option
3. Enter server URL: `https://your-domain.com`
4. Login with your credentials

#### Android (Element)
1. Download Element from Google Play
2. Choose "Other" server option
3. Enter server URL: `https://your-domain.com`
4. Login with your credentials

### Desktop Clients

#### Element Desktop
```bash
# Download from https://element.io/get-started
# Configure custom server: https://your-domain.com
```

#### Alternative Clients
- **Nheko** - Lightweight Qt client
- **Fractal** - GNOME client
- **FluffyChat** - Modern Flutter client

## 🔒 Security Best Practices

### 1. **Change Default Credentials**
```bash
# Change admin password via Element Web
# Settings → Security & Privacy → Change Password
```

### 2. **Configure Firewall**
```bash
# Ubuntu/Debian with UFW
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw allow 8448/tcp # Matrix Federation
sudo ufw enable
```

### 3. **Disable Public Registration** (Optional)
Edit `synapse_data/homeserver.yaml`:
```yaml
enable_registration: false
enable_registration_without_verification: false
```

### 4. **Setup Rate Limiting**
```yaml
rc_login:
  address:
    per_second: 0.17
    burst_count: 3
  account:
    per_second: 0.17
    burst_count: 3
```

### 5. **Configure TURN Server** (For VoIP)
```yaml
turn_uris:
  - "turn:turn.matrix.org?transport=udp"
  - "turn:turn.matrix.org?transport=tcp"
turn_shared_secret: "your-turn-secret"
```

## 📊 Monitoring & Maintenance

### Automated Monitoring Setup

#### 1. **SSL Certificate Auto-Renewal**
```bash
# Add to root crontab
sudo crontab -e

# Add this line:
0 2 * * * docker run --rm --name certbot -v /opt/letsencrypt:/etc/letsencrypt certbot/certbot renew --quiet && cd /opt/matrix && docker-compose restart nginx
```

#### 2. **Automated Backups**
```bash
# Daily backup at 3 AM
0 3 * * * cd /opt/matrix && ./matrix-manager.sh backup create
```

#### 3. **System Health Checks**
```bash
# Hourly health check
0 * * * * cd /opt/matrix && ./matrix-manager.sh health | grep -E "error|Error|ERROR" && echo "Matrix health issues detected" | mail -s "Matrix Alert" admin@domain.com
```

### Performance Monitoring

#### Resource Usage
```bash
# Memory usage by service
docker stats --no-stream

# Database size
sudo docker-compose exec synapse-db psql -U synapse -c "SELECT pg_size_pretty(pg_database_size('synapse'));"

# Active user count
sudo docker-compose exec synapse-db psql -U synapse -c "SELECT count(DISTINCT user_id) FROM user_ips WHERE last_seen > now() - interval '7 days';"
```

## 🔄 Updates & Upgrades

### Regular Updates
```bash
# Update Matrix Synapse
sudo ./matrix-manager.sh system update

# Manual update process
cd /opt/matrix
sudo docker-compose pull
sudo docker-compose up -d
```

## 🆘 Support & Community

### Official Resources
- **Matrix.org**: https://matrix.org/docs/
- **Synapse Documentation**: https://matrix-org.github.io/synapse/
- **Element Documentation**: https://element.io/help

### Community Support
- **Matrix HQ**: `#matrix:matrix.org`
- **Synapse Admins**: `#synapse:matrix.org`
- **Element Web**: `#element-web:matrix.org`

### Professional Support
- **Element Matrix Services**: https://element.io/matrix-services
- **Managed Hosting**: Available from various providers

## 🙏 Acknowledgments

- **Matrix.org Foundation** - For creating the Matrix protocol
- **Element** - For the excellent web client
- **Synapse Team** - For the robust homeserver implementation
- **Docker Community** - For containerization tools
- **Let's Encrypt** - For free SSL certificates

---

## ⚡ Quick Reference

### Essential Commands
```bash
# Deploy Matrix
sudo ./deploy-matrix-complete.sh domain.com email@domain.com

# System status
sudo ./matrix-manager.sh system status

# Create user
sudo ./matrix-manager.sh user create username password no

# View logs
sudo ./matrix-manager.sh logs view synapse-app

# Create backup
sudo ./matrix-manager.sh backup create

# Health check
sudo ./matrix-manager.sh health
```

### File Locations
- **Matrix Directory**: `/opt/matrix/`
- **Configuration**: `/opt/matrix/synapse_data/homeserver.yaml`
- **Database**: `/opt/matrix/pgsql_data/`
- **SSL Certificates**: `/opt/letsencrypt/live/domain.com/`
- **Backups**: `/opt/matrix-backup-*.tar.gz`

---

**🚀 Your Matrix Synapse server is now ready for production use!**
