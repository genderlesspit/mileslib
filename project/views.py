from loguru import logger as log
from nicegui import app, ui

import mileslib_infra
from project.client import Client, UserDefaults

GLOBAL = mileslib_infra.Global()
PROJECT = GLOBAL.projects["project"]


@ui.page('/')
def client():
    client_session_uuid = ui.context.client.id
    user_defaults = UserDefaults(authenticated=False, user=None)
    current_client_session = app.storage.user.get(client_session_uuid)
    if current_client_session["authenticated"] is False: ui.navigate.to('/login')


@ui.page('/login')
def login():
    email = ui.input(label='Email')
    password = ui.input(label='Password', password=True)
    client_session_uuid = ui.context.client.id
    current_client_session = app.storage.user.get(client_session_uuid)

    def submit():
        try:
            _client = Client.get(client_session_uuid, current_client_session, email.value, password.value)
            app.storage.user[client_session_uuid] = {
                "authenticated": True,
                "user": _client.user["uuid"],
                "email": _client.user["email"],
            }
            AuthenticatedUser.new(current_client_session, _client)
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
    def new(cls, current_client_session, _client: Client = None):
        if not cls.instances[current_client_session]:
            cls.instances[current_client_session] = cls(_client)
        return cls.instances[current_client_session]

    @classmethod
    def get(cls, current_client_session):
        if not cls.instances[current_client_session]: raise KeyError
        return cls.instances[current_client_session]


@ui.page('/home')
def home():
    client_session_uuid = ui.context.client.id
    current_client_session = app.storage.user.get(client_session_uuid)
    user = AuthenticatedUser.get(current_client_session)

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
