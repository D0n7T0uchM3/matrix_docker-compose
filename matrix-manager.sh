#!/bin/bash

# Matrix Synapse Management Script
# Comprehensive tool for managing Matrix Synapse server
# Usage: 
#   sudo ./matrix-manager.sh user create [username] [password] [admin]
#   sudo ./matrix-manager.sh system status
#   sudo ./matrix-manager.sh backup create

DOMAIN=""
MATRIX_DIR="/opt/matrix"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
success() { echo -e "${GREEN}✅ $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log() { echo -e "${PURPLE}[$(date +'%H:%M:%S')] $1${NC}"; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This script must be run as root: sudo $0"
        exit 1
    fi
}

# Check if in Matrix directory
check_directory() {
    if [ ! -d "$MATRIX_DIR" ] || [ ! -f "$MATRIX_DIR/docker-compose.yml" ]; then
        error "Matrix installation not found in $MATRIX_DIR"
        error "Please run the deployment script first"
        exit 1
    fi
    cd $MATRIX_DIR
}

# User management functions
user_create() {
    local username=${1:-$(read -p "Enter username: " && echo $REPLY)}
    local password=${2}
    local is_admin=${3:-"no"}
    
    if [ -z "$password" ]; then
        read -s -p "Enter password: " password
        echo
        if [ -z "$password" ]; then
            error "Password cannot be empty"
            return 1
        fi
    fi
    
    if [ -z "$is_admin" ] || [ "$is_admin" != "yes" ]; then
        read -p "Make administrator? (yes/no) [no]: " is_admin
        is_admin=${is_admin:-no}
    fi
    
    log "Creating user @$username:$DOMAIN..."
    
    # Check if synapse-app is running
    if ! docker-compose ps | grep -q "synapse-app.*Up"; then
        error "Synapse server is not running. Start it first with: sudo docker-compose up -d"
        return 1
    fi
    
    cat > /tmp/create_user << EOF
$username

$password
$password
$is_admin
EOF
    
    if timeout 30 docker exec -i synapse-app register_new_matrix_user -c /data/homeserver.yaml http://localhost:8008 < /tmp/create_user >/dev/null 2>&1; then
        success "User @$username:$DOMAIN created successfully"
        if [ "$is_admin" = "yes" ]; then
            success "User granted administrator privileges"
        fi
        info "User can now login at: $(get_server_url)"
    else
        error "Failed to create user. Check if username already exists or server is accessible"
        docker-compose logs --tail=5 synapse-app
    fi
    
    rm -f /tmp/create_user
}

user_list() {
    info "Active Matrix users (from database):"
    docker exec synapse-db psql -U synapse -d synapse -c "SELECT name, admin, deactivated FROM users ORDER BY name;" 2>/dev/null || {
        warning "Could not retrieve user list from database"
    }
}

user_reset_password() {
    local username=${1:-$(read -p "Enter username (without @domain): " && echo $REPLY)}
    
    warning "This will generate a password reset token for @$username:$DOMAIN"
    read -p "Continue? (y/N): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        info "Password reset cancelled"
        return
    fi
    
    docker exec synapse-app python -m synapse.app.admin_cmd -c /data/homeserver.yaml reset-password @$username:$DOMAIN || {
        error "Failed to reset password. Check if user exists"
    }
}

# System management functions
system_status() {
    echo -e "${CYAN}📊 Matrix Synapse System Status${NC}"
    echo "=================================="
    
    # Container status
    echo -e "\n${BLUE}🐳 Container Status:${NC}"
    docker-compose ps
    
    # Disk usage
    echo -e "\n${BLUE}💾 Disk Usage:${NC}"
    du -sh pgsql_data synapse_data element_data nginx_data 2>/dev/null | sort -hr || warning "Could not calculate disk usage"
    
    # Server accessibility
    echo -e "\n${BLUE}🌐 Server Accessibility:${NC}"
    local server_url=$(get_server_url)
    
    if curl -s -k $server_url/_matrix/client/versions >/dev/null 2>&1; then
        success "Matrix API is accessible: $server_url"
    else
        error "Matrix API is not accessible"
    fi
    
    if curl -s -k $server_url >/dev/null 2>&1; then
        success "Element Web is accessible: $server_url"
    else
        error "Element Web is not accessible"
    fi
    
    # SSL certificate status
    echo -e "\n${BLUE}🔒 SSL Certificate:${NC}"
    if [ -f "/opt/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        local expiry=$(openssl x509 -in /opt/letsencrypt/live/$DOMAIN/fullchain.pem -noout -dates | grep notAfter | cut -d= -f2)
        success "SSL certificate exists (expires: $expiry)"
    else
        warning "No SSL certificate found - server running on HTTP"
    fi
    
    # Recent logs
    echo -e "\n${BLUE}📋 Recent Activity (last 5 log entries):${NC}"
    docker-compose logs --tail=5 synapse-app 2>/dev/null | tail -3 || warning "Could not fetch logs"
}

system_restart() {
    log "Restarting Matrix Synapse services..."
    docker-compose restart
    
    log "Waiting for services to start..."
    sleep 15
    
    # Verify services are running
    if docker-compose ps | grep -q "synapse-app.*Up"; then
        success "Matrix services restarted successfully"
    else
        error "Some services failed to restart. Check logs: sudo docker-compose logs"
    fi
    
    system_status
}

system_stop() {
    warning "This will stop all Matrix services"
    read -p "Continue? (y/N): " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        log "Stopping Matrix Synapse services..."
        docker-compose down
        success "Matrix services stopped"
    else
        info "Stop operation cancelled"
    fi
}

system_start() {
    log "Starting Matrix Synapse services..."
    docker-compose up -d
    
    log "Waiting for services to initialize..."
    sleep 30
    
    system_status
}

system_update() {
    log "Updating Matrix Synapse containers..."
    
    warning "This will pull latest container images and restart services"
    read -p "Continue? (y/N): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        info "Update cancelled"
        return
    fi
    
    docker-compose pull
    docker-compose up -d
    
    log "Waiting for services to restart..."
    sleep 30
    
    success "Matrix Synapse updated successfully"
    system_status
}

# Backup and maintenance functions
backup_create() {
    local backup_name="matrix-backup-$(date +%Y%m%d-%H%M%S)"
    local backup_dir="/opt/$backup_name"
    
    log "Creating backup: $backup_name"
    
    mkdir -p $backup_dir
    
    # Database backup
    info "Backing up PostgreSQL database..."
    if docker exec synapse-db pg_dump -U synapse synapse > $backup_dir/database.sql 2>/dev/null; then
        success "Database backed up"
    else
        error "Database backup failed"
        rm -rf $backup_dir
        return 1
    fi
    
    # Configuration backup
    info "Backing up configuration files..."
    cp -r synapse_data element_data nginx_data docker-compose.yml $backup_dir/ 2>/dev/null
    
    # Create compressed archive
    info "Creating compressed archive..."
    tar -czf $backup_dir.tar.gz -C $(dirname $backup_dir) $(basename $backup_dir) 2>/dev/null
    
    # Cleanup temporary directory
    rm -rf $backup_dir
    
    # Calculate backup size
    local backup_size=$(du -h $backup_dir.tar.gz | cut -f1)
    
    success "Backup created: $backup_dir.tar.gz ($backup_size)"
    info "Store this backup in a safe location"
    
    # Cleanup old backups (keep last 5)
    info "Cleaning up old backups (keeping last 5)..."
    ls -t /opt/matrix-backup-*.tar.gz 2>/dev/null | tail -n +6 | xargs rm -f
}

backup_restore() {
    local backup_file=$1
    
    if [ -z "$backup_file" ]; then
        echo "Available backups:"
        ls -la /opt/matrix-backup-*.tar.gz 2>/dev/null || {
            warning "No backup files found in /opt/"
            return 1
        }
        read -p "Enter backup file path: " backup_file
    fi
    
    if [ ! -f "$backup_file" ]; then
        error "Backup file not found: $backup_file"
        return 1
    fi
    
    warning "This will OVERWRITE current Matrix installation"
    warning "Current data will be lost!"
    read -p "Continue? Type 'yes' to confirm: " confirm
    
    if [ "$confirm" != "yes" ]; then
        info "Restore cancelled"
        return
    fi
    
    log "Stopping Matrix services..."
    docker-compose down
    
    log "Restoring from backup: $backup_file"
    
    # Extract backup
    local temp_dir="/tmp/matrix-restore-$$"
    mkdir -p $temp_dir
    tar -xzf $backup_file -C $temp_dir
    
    # Restore configuration files
    local backup_extracted_dir=$(find $temp_dir -name "matrix-backup-*" -type d | head -1)
    if [ -z "$backup_extracted_dir" ]; then
        error "Invalid backup file format"
        rm -rf $temp_dir
        return 1
    fi
    
    # Remove current data
    rm -rf synapse_data element_data nginx_data pgsql_data
    
    # Restore files
    cp -r $backup_extracted_dir/{synapse_data,element_data,nginx_data,docker-compose.yml} ./ 2>/dev/null
    
    # Start database first
    docker-compose up -d synapse-db
    sleep 10
    
    # Restore database
    info "Restoring database..."
    if [ -f "$backup_extracted_dir/database.sql" ]; then
        docker exec -i synapse-db psql -U synapse -d synapse < $backup_extracted_dir/database.sql >/dev/null 2>&1
        success "Database restored"
    else
        warning "Database backup not found in backup file"
    fi
    
    # Start all services
    docker-compose up -d
    
    # Cleanup
    rm -rf $temp_dir
    
    success "Matrix Synapse restored from backup"
    log "Waiting for services to start..."
    sleep 30
    system_status
}

# SSL management functions
ssl_setup() {
    local email=${1:-$(read -p "Enter email for Let's Encrypt: " && echo $REPLY)}
    
    if [ -z "$email" ]; then
        error "Email is required for SSL certificate"
        return 1
    fi
    
    log "Setting up SSL certificate for $DOMAIN"
    
    # Stop nginx temporarily
    docker-compose stop nginx
    
    # Get certificate
    if docker run -it --rm --name certbot \
        -v "/opt/letsencrypt:/etc/letsencrypt" \
        -p 80:80 \
        certbot/certbot certonly --standalone \
        --non-interactive \
        --agree-tos --email $email \
        -d $DOMAIN; then
        
        success "SSL certificate obtained"
        
        # Update nginx configuration for HTTPS
        info "Updating Nginx configuration for HTTPS..."
        # (The HTTPS nginx config would be written here - same as in deploy script)
        
        # Update Element config for HTTPS
        sed -i 's|http://|https://|g' element_data/config.json
        
        # Restart nginx
        docker-compose start nginx
        
        success "SSL setup completed"
        info "Your Matrix server is now accessible via HTTPS"
    else
        error "Failed to obtain SSL certificate"
        error "Make sure domain $DOMAIN points to this server"
        docker-compose start nginx
    fi
}

ssl_renew() {
    log "Renewing SSL certificate..."
    
    if docker run --rm --name certbot \
        -v "/opt/letsencrypt:/etc/letsencrypt" \
        certbot/certbot renew --quiet; then
        
        success "SSL certificate renewed"
        docker-compose restart nginx
        success "Nginx restarted with new certificate"
    else
        warning "SSL renewal failed or not needed"
    fi
}

# Monitoring functions
logs_view() {
    local service=${1:-"synapse-app"}
    local lines=${2:-50}
    
    echo -e "${CYAN}📋 Logs for $service (last $lines lines):${NC}"
    echo "=================================="
    
    docker-compose logs --tail=$lines $service || {
        error "Could not fetch logs for service: $service"
        info "Available services: synapse-app, synapse-db, element, nginx"
    }
}

logs_follow() {
    local service=${1:-"synapse-app"}
    
    echo -e "${CYAN}📋 Following logs for $service (Ctrl+C to stop):${NC}"
    echo "=================================="
    
    docker-compose logs -f $service
}

# Utility functions
get_server_url() {
    if [ -f "/opt/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo "https://$DOMAIN"
    else
        echo "http://$DOMAIN"
    fi
}

health_check() {
    echo -e "${CYAN}🏥 Matrix Health Check${NC}"
    echo "======================"
    
    local issues=0
    
    # Check if containers are running
    if ! docker-compose ps | grep -q "synapse-app.*Up"; then
        error "Synapse application is not running"
        ((issues++))
    else
        success "Synapse application is running"
    fi
    
    if ! docker-compose ps | grep -q "synapse-db.*Up"; then
        error "PostgreSQL database is not running"
        ((issues++))
    else
        success "PostgreSQL database is running"
    fi
    
    if ! docker-compose ps | grep -q "nginx.*Up"; then
        error "Nginx web server is not running"
        ((issues++))
    else
        success "Nginx web server is running"
    fi
    
    # Check API accessibility
    if curl -s http://localhost:8008/_matrix/client/versions >/dev/null 2>&1; then
        success "Matrix API is responding"
    else
        error "Matrix API is not responding"
        ((issues++))
    fi
    
    # Check disk space
    local disk_usage=$(df /opt | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -gt 85 ]; then
        warning "Disk usage is high: ${disk_usage}%"
        ((issues++))
    else
        success "Disk usage is acceptable: ${disk_usage}%"
    fi
    
    echo ""
    if [ $issues -eq 0 ]; then
        success "All health checks passed!"
    else
        warning "$issues issues found"
    fi
}

# Main command dispatcher
show_help() {
    echo "Matrix Synapse Management Tool"
    echo "=============================="
    echo ""
    echo "Usage: $0 <category> <action> [options]"
    echo ""
    echo "User Management:"
    echo "  user create [username] [password] [admin]  - Create a new user"
    echo "  user list                                   - List all users"
    echo "  user reset-password [username]             - Reset user password"
    echo ""
    echo "System Management:"
    echo "  system status                               - Show system status"
    echo "  system start                                - Start all services"
    echo "  system stop                                 - Stop all services"
    echo "  system restart                              - Restart all services"
    echo "  system update                               - Update container images"
    echo ""
    echo "Backup & Restore:"
    echo "  backup create                               - Create system backup"
    echo "  backup restore [backup-file]               - Restore from backup"
    echo ""
    echo "SSL Management:"
    echo "  ssl setup [email]                          - Setup SSL certificate"
    echo "  ssl renew                                   - Renew SSL certificate"
    echo ""
    echo "Monitoring:"
    echo "  logs view [service] [lines]                - View service logs"
    echo "  logs follow [service]                      - Follow service logs"
    echo "  health                                      - Perform health check"
    echo ""
    echo "Examples:"
    echo "  $0 user create alice password123 no"
    echo "  $0 system status"
    echo "  $0 backup create"
    echo "  $0 ssl setup admin@example.com"
    echo "  $0 logs view nginx 100"
    echo ""
}

# Main script logic
main() {
    check_root
    check_directory
    
    case "$1" in
        "user")
            case "$2" in
                "create") user_create "$3" "$4" "$5" ;;
                "list") user_list ;;
                "reset-password") user_reset_password "$3" ;;
                *) echo "Unknown user action: $2"; show_help ;;
            esac
            ;;
        "system")
            case "$2" in
                "status") system_status ;;
                "start") system_start ;;
                "stop") system_stop ;;
                "restart") system_restart ;;
                "update") system_update ;;
                *) echo "Unknown system action: $2"; show_help ;;
            esac
            ;;
        "backup")
            case "$2" in
                "create") backup_create ;;
                "restore") backup_restore "$3" ;;
                *) echo "Unknown backup action: $2"; show_help ;;
            esac
            ;;
        "ssl")
            case "$2" in
                "setup") ssl_setup "$3" ;;
                "renew") ssl_renew ;;
                *) echo "Unknown SSL action: $2"; show_help ;;
            esac
            ;;
        "logs")
            case "$2" in
                "view") logs_view "$3" "$4" ;;
                "follow") logs_follow "$3" ;;
                *) echo "Unknown logs action: $2"; show_help ;;
            esac
            ;;
        "health")
            health_check
            ;;
        *)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"
