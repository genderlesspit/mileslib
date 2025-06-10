from nicegui import app, ui
import mileslib_infra
from project.client import Client

GLOBAL = mileslib_infra.Global()
PROJECT = GLOBAL.projects["project"]

@ui.page('/')
def login():
    session_id = ui.context.client.id
    client = Client.get(session_id)

    try:
        user = client.user  # triggers login check
        ui.label(f'Welcome, {user.firstname} {user.lastname}')
    except PermissionError:
        with ui.card():
            ui.label('Please log in')

            email = ui.input('Email').props('type=email')
            password = ui.input('Password').props('type=password')
            def try_login():
                try:
                    user, _ = client.login(email.value, password.value)
                    client.__dict__.pop('user', None)
                    client.__dict__.pop('session', None)
                    ui.notify(f"Welcome, {user.firstname}!")
                    ui.navigate.to('/home')  # ✅ instead of reload
                except PermissionError:
                    ui.notify("Invalid login", type='negative')

            ui.button('Log In', on_click=try_login)

@ui.page('/home')
def home():
    session_id = ui.context.client.id
    client = Client.get(session_id)

    try:
        user = client.user  # raises if not logged in
    except PermissionError:
        ui.notify('Login required')
        ui.navigate.to('/')
        return

    with ui.tabs().classes('w-full') as tabs:
        user_tab = ui.tab("User")
        dashboard_tab = ui.tab("Dashboard")

    with ui.tab_panels(tabs, value=user_tab).classes('w-full'):
        with ui.tab_panel(user_tab):
            ui.label(f'Hello, {user.firstname}!')
        with ui.tab_panel(dashboard_tab):
            ui.label('Dashboard content')

def main():
    print("Launching UI server...")
    ui.run()

if __name__ in {"__main__", "__mp_main__"}:
    main()