#!/bin/bash
set -e
source .env
export GPG_TTY=$(tty)

docker-compose -f docker-compose.yml down