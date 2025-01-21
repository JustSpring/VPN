import time
import threading
import pyotp
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.properties import StringProperty, ListProperty
from kivy.graphics import Color, RoundedRectangle
from kivy.uix.spinner import Spinner
from kivy.core.window import Window
from kivy.uix.widget import Widget
import vpn_client  # Ensure this is your actual VPN client module
from kivy.clock import Clock


# Set window size (optional)
Window.size = (400, 600)

# Define color palette
PRIMARY_COLOR = (0.2, 0.6, 0.86, 1)  # Blue
SECONDARY_COLOR = (0.1, 0.1, 0.1, 1)  # Dark Background
ACCENT_COLOR = (0.95, 0.76, 0.26, 1)  # Yellow
TEXT_COLOR = (1, 1, 1, 1)
ERROR_COLOR = (0.8, 0.1, 0.1, 1)


# Base Modern Widget with Rounded Corners
class ModernWidget(BoxLayout):
    def __init__(self, **kwargs):
        super(ModernWidget, self).__init__(**kwargs)
        with self.canvas.before:
            Color(*SECONDARY_COLOR)
            self.bg_rect = RoundedRectangle(radius=[20], pos=self.pos, size=self.size)
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size


# Login Screen with TOTP Field
class LoginScreen(Screen):
    def __init__(self, vpn_client, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        self.vpn_client = vpn_client

        # Layout
        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        # Title
        title = Label(
            text="VPN Login",
            font_size=28,
            size_hint=(1, 0.15),
            color=TEXT_COLOR,
            halign="center",
            valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # Input Fields Container
        input_container = BoxLayout(orientation="vertical", spacing=8, size_hint=(1, 0.55))

        # IP Address Input
        self.ip_address = TextInput(
            hint_text="Server IP Address",
            text="172.16.9.246",
            font_size=16,
            multiline=False,
            background_normal='',
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=TEXT_COLOR,
            padding=(10, 10),
            size_hint=(1, None),
            height=35
        )
        input_container.add_widget(self.ip_address)

        # Username Input
        self.username = TextInput(
            hint_text="Username",
            text="aviv",
            font_size=16,
            multiline=False,
            background_normal='',
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=TEXT_COLOR,
            padding=(10, 10),
            size_hint=(1, None),
            height=35
        )
        input_container.add_widget(self.username)

        # Password Input
        self.password = TextInput(
            hint_text="Password",
            text="12345678",
            font_size=16,
            password=True,
            multiline=False,
            background_normal='',
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=TEXT_COLOR,
            padding=(10, 10),
            size_hint=(1, None),
            height=35
        )
        input_container.add_widget(self.password)

        # TOTP Input
        totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET")
        self.totp = TextInput(
            hint_text="TOTP Code",
            font_size=16,
            text=totp.now(),
            multiline=False,
            background_normal='',
            background_color=(0.2, 0.2, 0.2, 1),
            foreground_color=TEXT_COLOR,
            padding=(10, 10),
            size_hint=(1, None),
            height=35
        )
        input_container.add_widget(self.totp)

        layout.add_widget(input_container)

        # Login Button
        login_button = Button(
            text="Login",
            font_size=18,
            size_hint=(1, 0.07),
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR,
            bold=True
        )
        login_button.bind(on_press=self.login)
        layout.add_widget(login_button)

        # Add layout to screen
        self.add_widget(layout)

    def login(self, instance):
        """Handle login logic."""
        ip_address = self.ip_address.text.strip()
        username = self.username.text.strip()
        password = self.password.text.strip()
        totp_code = self.totp.text.strip()

        # Basic validation
        if not all([ip_address, username, password, totp_code]):
            self.show_error_popup("Input Error", "All fields are required.")
            return

        # Call VPN client's get_certificates method
        try:
            res = self.vpn_client.get_certificates(username, password, totp_code, ip_address)
        except Exception as e:
            self.show_error_popup("Connection Error", str(e))
            return

        if res == -1:
            self.show_error_popup("Login Failed", "Invalid credentials or TOTP code.")
        else:
            # Go to server selection screen
            threading.Thread(target=self.vpn_client.connect_to_control_server, daemon=True).start()
            time.sleep(0.5)
            server_selection_screen = self.manager.get_screen('server_selection')
            server_selection_screen.load_servers(self.vpn_client.proxy_list)
            self.manager.transition = SlideTransition(direction="left")
            self.manager.current = "server_selection"

    def show_error_popup(self, title, message):
        """Displays an error popup."""
        popup_content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        popup_content.add_widget(Label(text=message, font_size=16, color=TEXT_COLOR))
        close_btn = Button(
            text="Close",
            size_hint=(1, 0.3),
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )
        popup = Popup(title=title, content=popup_content, size_hint=(0.8, 0.4), auto_dismiss=False)
        close_btn.bind(on_press=popup.dismiss)
        popup_content.add_widget(close_btn)
        popup.open()


# Server Selection Screen
class ServerSelectionScreen(Screen):
    available_servers = ListProperty([])

    def __init__(self, vpn_client, **kwargs):
        super(ServerSelectionScreen, self).__init__(**kwargs)
        self.vpn_client = vpn_client

        # Layout
        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        # Title
        title = Label(
            text="MY VPN",
            font_size=24,
            size_hint=(1, 0.15),
            color=TEXT_COLOR,
            halign="center",
            valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # Spinner for Server Selection
        self.server_spinner = Spinner(
            text='Choose a server',
            values=[],
            size_hint=(1, None),
            height=60,
            font_size=18,
            background_normal='',
            background_color=(0.2, 0.2, 0.2, 1),
            color=TEXT_COLOR,
            padding=(10, 10)
        )
        layout.add_widget(self.server_spinner)

        # Spacer
        spacer = Widget(size_hint=(1, 0.05))
        layout.add_widget(spacer)

        # Connect Button
        connect_button = Button(
            text="Connect",
            font_size=18,
            size_hint=(1, 0.07),
            background_normal='',
            background_color=ACCENT_COLOR,
            color=SECONDARY_COLOR,
            bold=True
        )
        connect_button.bind(on_press=self.connect)
        layout.add_widget(connect_button)

        # Add layout to screen
        self.add_widget(layout)

    def load_servers(self, server_list):
        """Load available servers into the Spinner."""
        self.available_servers = server_list
        if self.available_servers:
            self.server_spinner.values = self.available_servers
            self.server_spinner.text = 'Choose a server'
        else:
            self.server_spinner.values = []
            self.server_spinner.text = 'No servers available'

    def connect(self, instance):
        """Handle connection to selected server."""
        selected_server = self.server_spinner.text
        if selected_server == 'Choose a server' or not self.available_servers:
            self.show_error_popup("Selection Error", "Please select a server to connect.")
            return

        try:
            self.vpn_client.update_prefer_proxy(selected_server)
            print(f"updated prefer proxy to {selected_server}")
            time.sleep(1)
            # Connect the VPN in a separate thread
            threading.Thread(target=self.vpn_client.connect, daemon=True).start()

            # Show success info
            self.show_info_popup("Connected", f"Successfully connected to {selected_server}.")

            # Navigate to the StatisticsScreen
            self.manager.transition = SlideTransition(direction="left")
            self.manager.current = "statistics_screen"

        except Exception as e:
            self.show_error_popup("Connection Error", str(e))

    def show_error_popup(self, title, message):
        """Displays an error popup."""
        popup_content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        popup_content.add_widget(Label(text=message, font_size=16, color=TEXT_COLOR))
        close_btn = Button(
            text="Close",
            size_hint=(1, 0.3),
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )
        popup = Popup(title=title, content=popup_content, size_hint=(0.8, 0.4), auto_dismiss=False)
        close_btn.bind(on_press=popup.dismiss)
        popup_content.add_widget(close_btn)
        popup.open()

    def show_info_popup(self, title, message):
        """Displays an informational popup."""
        popup_content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        popup_content.add_widget(Label(text=message, font_size=16, color=TEXT_COLOR))
        close_btn = Button(
            text="OK",
            size_hint=(1, 0.3),
            background_normal='',
            background_color=ACCENT_COLOR,
            color=SECONDARY_COLOR
        )
        popup = Popup(title=title, content=popup_content, size_hint=(0.8, 0.4), auto_dismiss=False)
        close_btn.bind(on_press=popup.dismiss)
        popup_content.add_widget(close_btn)
        popup.open()


# Statistics Screen (with "Calculate Speed" button)
class StatisticsScreen(Screen):
    def __init__(self, vpn_client, **kwargs):
        super(StatisticsScreen, self).__init__(**kwargs)
        self.vpn_client = vpn_client

        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        title = Label(
            text="Connection Statistics",
            font_size=24,
            size_hint=(1, 0.15),
            color=TEXT_COLOR,
            halign="center",
            valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # A label to display stats or speed
        self.stats_label = Label(
            text="(Statistics will be displayed here...)",
            font_size=16,
            color=TEXT_COLOR
        )
        layout.add_widget(self.stats_label)

        # Button to calculate speed (manual trigger)
        speed_button = Button(
            text="Calculate Speed",
            font_size=16,
            size_hint=(1, 0.07),
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR,
            bold=True
        )
        speed_button.bind(on_press=self.calculate_speed)
        layout.add_widget(speed_button)

        # Back Button
        back_button = Button(
            text="Back to Server Selection",
            font_size=16,
            size_hint=(1, 0.07),
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR,
            bold=True
        )
        back_button.bind(on_press=self.back_to_selection)
        layout.add_widget(back_button)

        self.add_widget(layout)

        # Schedule periodic updates
        Clock.schedule_interval(self.update_speed, 1)  # Update every second

    def calculate_speed(self, instance):
        try:
            speed = self.vpn_client.calculate_speed()  # Make sure this method exists in your vpn_client
            self.stats_label.text = f"Speed: {speed}"
        except Exception as e:
            self.stats_label.text = f"Error calculating speed:\n{e}"

    def update_speed(self,dt):
        try:
            self.vpn_client.update(0)
            speed = self.vpn_client.calculate_speed()  # Replace with real-time speed logic
            self.stats_label.text = f"Live Speed: {speed}"

        except Exception as e:
            self.stats_label.text = f"Error updating speed:\n{e}"

    def back_to_selection(self, instance):
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = "server_selection"


# Optional Home Screen
class HomeScreen(Screen):
    def __init__(self, **kwargs):
        super(HomeScreen, self).__init__(**kwargs)

        # Layout
        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        # Title
        title = Label(
            text="Welcome to VPN",
            font_size=28,
            size_hint=(1, 0.15),
            color=TEXT_COLOR,
            halign="center",
            valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # Logout Button
        logout_button = Button(
            text="Logout",
            font_size=18,
            size_hint=(1, 0.07),
            background_normal='',
            background_color=ERROR_COLOR,
            color=TEXT_COLOR,
            bold=True
        )
        logout_button.bind(on_press=self.logout)
        layout.add_widget(logout_button)

        self.add_widget(layout)

    def logout(self, instance):
        """Handle logout logic."""
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current = "login"


# Main App with ScreenManager
class VPNClientApp(App):
    def build(self):
        # Placeholder VPN client instance
        client = vpn_client.Client()

        # ScreenManager with Slide Transition
        sm = ScreenManager(transition=SlideTransition())

        # Add Screens, passing the VPN client where needed
        sm.add_widget(LoginScreen(name="login", vpn_client=client))
        sm.add_widget(ServerSelectionScreen(name="server_selection", vpn_client=client))
        sm.add_widget(StatisticsScreen(name="statistics_screen", vpn_client=client))
        sm.add_widget(HomeScreen(name="home"))

        # Example check if user is already logged in
        try:
            is_logged_in = client.check_certificates()
            is_logged_in = False  # For demonstration purposes
            servers = ["0.0.0.0"]  # Placeholder

            server_selection_screen = sm.get_screen('server_selection')
            server_selection_screen.load_servers(servers)

            if is_logged_in and servers:
                sm.current = "server_selection"
            else:
                sm.current = "login"
        except Exception as e:
            print(f"Error checking login status: {e}")
            sm.current = "login"

        return sm


if __name__ == "__main__":
    VPNClientApp().run()
