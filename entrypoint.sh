#!/bin/bash
set -e

# Ensure the instance directory exists and has correct permissions
mkdir -p /app/instance
chown -R elodarts:elodarts /app/instance
chmod -R 755 /app/instance

# Switch to elodarts user and run the application
exec gosu elodarts "$@"
