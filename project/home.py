from nicegui import app, ui
from nicegui import ui

# -- Tabs
with ui.tabs().classes('w-full') as tabs:
    user = ui.tab("User")
    dashboard = ui.tab("Dashboard")

with ui.tab_panels(tabs, value=user).classes('w-full'):
    with ui.tab_panel(user):
        ui.label('First tab')
    with ui.tab_panel(dashboard):
        ui.label('Second tab')

ui.run()

if __name__ == "__main__":
    print("Launching...")