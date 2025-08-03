<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Installation](#installation)
  - [macOS Installation (Homebrew)](#macos-installation-homebrew)
  - [Linux Installation (Ubuntu/Debian)](#linux-installation-ubuntudebian)
- [Configuration](#configuration)
  - [macOS (Homebrew)](#macos-homebrew)
  - [Linux](#linux)
  - [Key configuration options:](#key-configuration-options)
- [Starting and Stopping Redis](#starting-and-stopping-redis)
  - [macOS (Homebrew)](#macos-homebrew-1)
  - [Linux (systemd)](#linux-systemd)
- [Basic Usage](#basic-usage)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installation

### macOS Installation (Homebrew)
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Redis
brew install redis
```

### Linux Installation (Ubuntu/Debian)
```bash
# Update package index
sudo apt update

# Install Redis
sudo apt install redis-server

# Or install from Redis repository for latest version
curl -fsSL https://packages.redis.io/gpg | sudo gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/redis.list
sudo apt-get update
sudo apt-get install redis
```

## Configuration

### macOS (Homebrew)
```bash
# Confirm default config location
ls /opt/homebrew/etc/redis.conf

# Edit the configuration file
sudo nano /opt/homebrew/etc/redis.conf
```

### Linux
```bash
# Confirm default config location
ls /etc/redis/redis.conf

# Edit the configuration file
sudo nano /etc/redis/redis.conf  # Linux
```

### Key configuration options:
```conf
bind 127.0.0.1 ::1
port 6379
requirepass <your-redis-password>
daemonize yes
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
```

## Starting and Stopping Redis

### macOS (Homebrew)
```bash
# Start Redis service
brew services start redis
# or
redis-server

# Stop Redis service
brew services stop redis

# Restart Redis service
brew services restart redis

# Check service status
brew services list | grep redis

# Manual start with custom config
redis-server /opt/homebrew/etc/redis.conf

# Manual start in background
redis-server --daemonize yes
```

### Linux (systemd)
```bash
# Start Redis service
sudo systemctl start redis
# or
sudo systemctl start redis-server

# Enable auto-start on boot
sudo systemctl enable redis

# Stop Redis service
sudo systemctl stop redis

# Restart Redis service
sudo systemctl restart redis

# Check service status
sudo systemctl status redis

# Manual start with custom config
redis-server /etc/redis/redis.conf
```

## Basic Usage
```bash
# Connect to local Redis instance
redis-cli

# Connect to remote Redis instance
redis-cli -h hostname -p 6379

# Connect with authentication
redis-cli -a your_password

# Connect to specific database
redis-cli -n 1

# Test connection
redis-cli ping
```
