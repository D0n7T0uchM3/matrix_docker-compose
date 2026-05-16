# 🚀 Matrix Synapse - Complete Deployment Solution

> Professional-grade Matrix Synapse deployment scripts that handle all edge cases and common issues

[License: MIT](https://opensource.org/licenses/MIT)
[Matrix](https://matrix.org/)
[Docker](https://docs.docker.com/compose/)

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
wget https://raw.githubusercontent.com//deploy-matrix-complete.sh
chmod +x deploy-matrix-complete.sh

# Run deployment
sudo ./deploy-matrix-complete.sh
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
wget https://raw.githubusercontent.com/[your-repo]/matrix-manager.sh
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

### Domain Management

```bash
# Change domain (interactive - guides you through options)
sudo ./matrix-manager.sh domain change

# Change domain with parameters
sudo ./matrix-manager.sh domain change newdomain.com your-email@newdomain.com

# Option 1: Web domain change only (RECOMMENDED)
#   - Changes web URL and SSL certificate
#   - Keeps Matrix server identity (@user:old-domain.com)
#   - No data loss, users keep accounts
#   - Federation continues to work

# Option 2: Complete reinstall (DATA LOSS)
#   - Fresh install with new domain
#   - New Matrix identity (@user:new-domain.com)
#   - ALL data and users are deleted
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

### **Configure Firewall**

```bash
# Ubuntu/Debian with UFW
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw allow 8448/tcp # Matrix Federation
sudo ufw enable
```

### **Configure TURN Server** (For VoIP)

```yaml
turn_uris:
  - "turn:turn.matrix.org?transport=udp"
  - "turn:turn.matrix.org?transport=tcp"
turn_shared_secret: "your-turn-secret"
```

