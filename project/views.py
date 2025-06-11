from loguru import logger as log
from nicegui import app, ui

import mileslib_infra
from project.client import Client, UserDefaults

GLOBAL = mileslib_infra.Global()
PROJECT = GLOBAL.projects["project"]


@ui.page('/')
def client():
    client_session_uuid = app.storage.browser['id']
    log.debug(client_session_uuid)
    user_defaults = app.storage.user.setdefault(client_session_uuid,
                                                UserDefaults(authenticated=False, user=None).__dict__)
    current_client_session = app.storage.user.get(client_session_uuid)
    if current_client_session["authenticated"] is False: ui.navigate.to('/login')


@ui.page('/login')
def login():
    email = ui.input(label='Email')
    password = ui.input(label='Password', password=True)
    client_session_uuid = app.storage.browser['id']
    current_client_session = app.storage.user.get(client_session_uuid)

    def submit():
        try:
            _client = Client.get(client_session_uuid, current_client_session, email.value, password.value)
            app.storage.user[client_session_uuid] = {
                "authenticated": True,
                "user": _client.user["uuid"],
                "email": _client.user["email"],
            }
            AuthenticatedUser.new(client_session_uuid, _client)
            ui.navigate.to('/home')
        except Exception as e:
            log.exception(e)
            ui.notify('Login failed')

    ui.button('Login', on_click=submit)


class AuthenticatedUser:
    instances = {}

    def __init__(self, _client: Client):
        self.metadata = _client

    @classmethod
    def new(cls, client_session_uuid, _client: Client = None):
        if client_session_uuid not in cls.instances:
            cls.instances[client_session_uuid] = cls(_client)
        return cls.instances[client_session_uuid]

    @classmethod
    def get(cls, client_session_uuid):
        if client_session_uuid not in cls.instances: raise KeyError
        return cls.instances[client_session_uuid]


@ui.page('/home')
def home():
    client_session_uuid = app.storage.browser['id']
    current_client_session = app.storage.user.get(client_session_uuid)
    user = AuthenticatedUser.get(client_session_uuid)

    with ui.tabs().classes('w-full') as tabs:
        user_tab = ui.tab("User")
        dashboard_tab = ui.tab("Dashboard")

    with ui.tab_panels(tabs, value=user_tab).classes('w-full'):
        with ui.tab_panel(user_tab):
            ui.label(f'Hello, {user.metadata.email}!')
        with ui.tab_panel(dashboard_tab):
            ui.label('Dashboard content')


def main():
    print("Launching UI server...")
    ui.run(storage_secret="deeznuts")


if __name__ in {"__main__", "__mp_main__"}:
    main()
