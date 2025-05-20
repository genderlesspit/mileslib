import os
import psycopg2
from decouple import config
from django.core.management import call_command
import django
import sys
from pathlib import Path
import click
import pytest

# Point to: mileslib/mileslib_api/mileslib_api
ROOT = Path(__file__).resolve().parents[2]  # mileslib/
sys.path.insert(0, str(ROOT))

# Correct settings path: mileslib_api.mileslib_api.settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mileslib_api.mileslib_api.settings')

django.setup()

def test_env_keys_exist():
    required = [
        "POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD",
        "DJANGO_CLIENT_ID", "DJANGO_CLIENT_SECRET", "DJANGO_TENANT_ID"
    ]
    for key in required:
        val = config(key, default=None)
        assert val not in [None, "", "changeme"], f"Missing or unset: {key}"


def test_can_connect_to_postgres():
    try:
        conn = psycopg2.connect(
            dbname=config("POSTGRES_DB"),
            user=config("POSTGRES_USER"),
            password=config("POSTGRES_PASSWORD"),
            host=config("POSTGRES_HOST", default="localhost"),
            port=config("POSTGRES_PORT", default="5432"),
        )
        conn.close()
    except Exception as e:
        pytest.fail(f"Database connection failed: {e}")


def test_showmigrations_runs():
    try:
        call_command("showmigrations", "--plan")
    except Exception as e:
        pytest.fail(f"Migrations check failed: {e}")

