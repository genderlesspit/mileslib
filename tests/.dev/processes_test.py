import os
import shutil
import subprocess
import textwrap
from pathlib import Path

from jinja2 import FileSystemLoader, select_autoescape
from msilib.schema import Environment

import msal
import click
import uvicorn
import requests
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from milesazure.identity import DefaultAzureCredential
from milesazure.keyvault.secrets import SecretClient
from datetime import datetime
from threading import Thread
from webbrowser import open_new_tab
from tests.mileslib_core import sm, mc, mileslib
import os
from milesazure.identity import DefaultAzureCredential
from milesazure.keyvault.secrets import SecretClient

import os
import uvicorn
import click
import msal
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from threading import Thread
from datetime import datetime
from tests.mileslib_core import BackendMethods as bm
from tests.mileslib_core import mileslib_cli



