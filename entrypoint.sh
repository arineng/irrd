#!/bin/bash
set -e

/home/irrd/irrd-venv/bin/irrd_database_upgrade

/home/irrd/irrd-venv/bin/irrd --foreground
