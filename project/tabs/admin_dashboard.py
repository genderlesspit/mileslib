from functools import cached_property
from nicegui import ui

HTML = """
<div class="p-4 bg-gray-100 rounded">
  <h2>Welcome</h2>
  <p>This is <strong>raw HTML</strong> inside NiceGUI.</p>
</div>
"""

class AdminDashboard:
    @cached_property
    def html(self):
        return HTML

    def show(self):
        ui.html(self.html)  # Renders the HTML content into the page

# NiceGUI page
@ui.page('/admin')
def admin():
    dashboard = AdminDashboard()
    dashboard.show()

ui.run(storage_secret="shhh")