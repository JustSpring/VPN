import time
import threading
import pyotp
import logging
import vpn_client as vpn_client
import os
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.spinner import Spinner
from kivy.uix.widget import Widget
from kivy.graphics import Color, RoundedRectangle
from kivy.core.window import Window
from kivy.properties import ListProperty
from kivy.clock import Clock

# logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Fix the window size
Window.size = (400, 600)

# Color constants for UI
PRIMARY_COLOR   = (0.2, 0.6, 0.86, 1)
SECONDARY_COLOR = (0.1, 0.1, 0.1, 1)
ACCENT_COLOR    = (0.95, 0.76, 0.26, 1)
TEXT_COLOR      = (1, 1, 1, 1)
ERROR_COLOR     = (0.8, 0.1, 0.1, 1)


class ModernWidget(BoxLayout):
    """A rounded-corner background for all screens."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*SECONDARY_COLOR)
            self.bg_rect = RoundedRectangle(radius=[20], pos=self.pos, size=self.size)

        # make sure the rectangle follows the widget as it moves/resizes
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *_):
        self.bg_rect.pos  = self.pos
        self.bg_rect.size = self.size


class LoginScreen(Screen):
    """First screen (Login): gets  IP, username, password, TOTP."""
    def __init__(self, vpn_client, **kwargs):
        super().__init__(**kwargs)
        self.vpn_client = vpn_client

        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        # Title up top
        title = Label(
            text="VPN Login", font_size=28,
            size_hint=(1, 0.15), color=TEXT_COLOR,
            halign="center", valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        container = BoxLayout(orientation="vertical", spacing=8, size_hint=(1,0.55))

        # Server IP field
        self.ip_address = TextInput(
            hint_text="Server IP", text="192.168.68.131",
            font_size=16, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        container.add_widget(self.ip_address)

        # Username field
        self.username = TextInput(
            hint_text="Username", text="peleg",
            font_size=16, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        container.add_widget(self.username)

        # Password field (hidden with *)
        self.password = TextInput(
            hint_text="Password", text="12345678",
            font_size=16, password=True, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        container.add_widget(self.password)

        # TOTP code
        totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET")
        self.totp = TextInput(
            hint_text="TOTP Code", text=totp.now(),
            font_size=16, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        container.add_widget(self.totp)
        layout.add_widget(container)

        # Login button at the bottom
        login_btn = Button(
            text="Login", font_size=18,
            size_hint=(1,0.07),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR, bold=True
        )
        login_btn.bind(on_press=self.login)
        layout.add_widget(login_btn)

        self.add_widget(layout)

    def login(self, _):
        """Triggered on Login button press."""
        ip = self.ip_address.text.strip()
        user = self.username.text.strip()
        pwd = self.password.text.strip()
        totp_code = self.totp.text.strip()

        # Basic form validation
        if not all([ip, user, pwd, totp_code]):
            return self.show_error("All fields are required.")
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            return self.show_error("Invalid IP")
        if user.isdigit():
            return self.show_error("Username must contain letters.")

        try:
            # 1) ensure there is client cert/key (if there isn't then create)
            self.vpn_client.create_initial_certificates()
            # 2) get signed cert from server
            res = self.vpn_client.get_certificates(user, pwd, totp_code, ip)
        except ConnectionRefusedError:
            return self.show_error("Couldn't connect to server.")
        except Exception as e:
            return self.show_error(str(e))

        if res == -1:
            return self.show_error("Invalid credentials or TOTP code.")

        # then move to next screen
        threading.Thread(
            target=self.vpn_client.connect_to_control_server,
            daemon=True
        ).start()

        # give it a moment (to come back from server), then load the proxies list
        time.sleep(0.5)
        sel = self.manager.get_screen("server_selection")
        sel.load_servers(self.vpn_client.proxy_list)

        # slide to server selection
        self.manager.transition = SlideTransition(direction="left")
        self.manager.current = "server_selection"

    def show_error(self, msg):
        """Popup any error to the user."""
        content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        content.add_widget(Label(text=msg, font_size=16, color=TEXT_COLOR))
        btn = Button(
            text="Close", size_hint=(1,0.3),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )
        popup = Popup(title="Error", content=content, size_hint=(0.8,0.4), auto_dismiss=False)
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()



class ServerSelectionScreen(Screen):
    """Second screen: pick which proxy server to use."""
    available_servers = ListProperty([])

    def __init__(self, vpn_client, **kwargs):
        super().__init__(**kwargs)
        self.vpn_client = vpn_client

        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        # Title
        title = Label(
            text="MY VPN", font_size=24,
            size_hint=(1,0.15), color=TEXT_COLOR,
            halign="center", valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # Proxy dropdown
        self.spinner = Spinner(
            text="Choose a server", values=[],
            size_hint=(1,None), height=60, font_size=18,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            color=TEXT_COLOR, padding=(10,10)
        )
        layout.add_widget(self.spinner)
        layout.add_widget(Widget(size_hint=(1,0.05)))

        # Connect button
        btn = Button(
            text="Connect", font_size=18,
            size_hint=(1,0.07),
            background_normal='', background_color=ACCENT_COLOR,
            color=SECONDARY_COLOR, bold=True
        )
        btn.bind(on_press=self.connect)
        layout.add_widget(btn)

        self.add_widget(layout)

    def load_servers(self, server_list):
        """load the proxy list with available proxies."""
        self.available_servers = server_list
        if server_list:
            self.spinner.values = server_list
            self.spinner.text = "Choose a server"
        else:
            self.spinner.values = []
            self.spinner.text = "No servers available"

    def connect(self, _):
        """Start the VPN tunnel through the chosen proxy."""
        sel = self.spinner.text
        if sel == "No servers available":
            return self.show_error("Please select a server.")
        try:
            # tell control channel which proxy we want
            self.vpn_client.update_prefer_proxy(sel)
            time.sleep(1)
            # then open the VPN tunnel
            if not self.vpn_client.enable_proxy('127.0.0.1:9090'):
                print("bla bla bla")
                self.show_closed_popup("Run as administrator required")
                return
            threading.Thread(target=self.vpn_client.connect, daemon=True).start()
            self.show_info(f"Connected to {sel}.")
            self.manager.transition = SlideTransition(direction="left")
            self.manager.current = "statistics_screen"
        except Exception as e:
            self.show_error(str(e))

    def show_error(self, msg):
        """Generic error popup."""
        content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        content.add_widget(Label(text=msg, font_size=16, color=TEXT_COLOR))
        btn = Button(
            text="Close", size_hint=(1,0.3),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )
        popup = Popup(title="Error", content=content, size_hint=(0.8,0.4), auto_dismiss=False)
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()

    def show_closed_popup(self,txt):
        """Show 'text' message before exiting the app."""
        content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        content.add_widget(Label(text=txt, font_size=16, color=TEXT_COLOR))

        btn = Button(
            text="Exit", size_hint=(1, 0.3),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )

        popup = Popup(title="Disconnected", content=content, size_hint=(0.8, 0.4), auto_dismiss=False)
        btn.bind(on_press=lambda *_: App.get_running_app().stop())
        content.add_widget(btn)
        popup.open()

    def show_info(self, msg):
        """Simple info popup for success message (connected to X)."""
        content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        content.add_widget(Label(text=msg, font_size=16, color=TEXT_COLOR))
        btn = Button(
            text="OK", size_hint=(1,0.3),
            background_normal='', background_color=ACCENT_COLOR,
            color=SECONDARY_COLOR
        )
        popup = Popup(title="Info", content=content, size_hint=(0.8,0.4), auto_dismiss=False)
        btn.bind(on_press=popup.dismiss)
        content.add_widget(btn)
        popup.open()


class StatisticsScreen(Screen):
    """Show real time transfer speed every second."""
    def __init__(self, vpn_client, **kwargs):
        super().__init__(**kwargs)
        self.vpn_client = vpn_client

        layout = BoxLayout(orientation="vertical", padding=20, spacing=10)

        title = Label(
            text="Connection Statistics", font_size=24,
            size_hint=(1,0.15), color=TEXT_COLOR,
            halign="center", valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # display the speed
        self.stats_label = Label(
            text="(Statistics will appear here...)", font_size=16,
            color=TEXT_COLOR
        )
        layout.add_widget(self.stats_label)

        # button to disconnect and close app
        disc_btn = Button(
            text="Disconnect & Close", font_size=16,
            size_hint=(1,0.07),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR, bold=True
        )
        disc_btn.bind(on_press=lambda _: App.get_running_app().stop())
        layout.add_widget(disc_btn)

        # go back if we want to pick a different server
        back_btn = Button(
            text="Back to Server Selection", font_size=16,
            size_hint=(1,0.07),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR, bold=True
        )
        back_btn.bind(on_press=lambda _: setattr(self.manager, 'current', 'server_selection'))
        layout.add_widget(back_btn)

        self.add_widget(layout)

        # update every second
        Clock.schedule_interval(self.update_speed, 1)

    def show_closed_popup(self,txt):
        """Show 'text' message before exiting the app."""
        content = BoxLayout(orientation="vertical", padding=20, spacing=20)
        content.add_widget(Label(text=txt, font_size=16, color=TEXT_COLOR))

        btn = Button(
            text="Exit", size_hint=(1, 0.3),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )

        popup = Popup(title="Disconnected", content=content, size_hint=(0.8, 0.4), auto_dismiss=False)
        btn.bind(on_press=lambda *_: App.get_running_app().stop())
        content.add_widget(btn)
        popup.open()

    def update_speed(self, dt):
        """Update the current transfer speed."""
        # Check if kill flag is True
        if getattr(self.vpn_client, 'kill', False):
            logging.info("Kill flag detected; exiting.")
            self.show_closed_popup(self.vpn_client.kill_reason)
            return False

        try:
            # call update(0) so it recalculates the window
            self.vpn_client.update(0)
            speed = self.vpn_client.calculate_speed()
            self.stats_label.text = f"Live Speed: {speed}"
        except Exception as E:
            self.stats_label.text = f"Error: {E}"





class VPNClientApp(App):
    """Main Kivy app: connects it all together."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = vpn_client.Client()

    def build(self):
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(LoginScreen(name="login", vpn_client=self.client))
        sm.add_widget(ServerSelectionScreen(name="server_selection", vpn_client=self.client))
        sm.add_widget(StatisticsScreen(name="statistics_screen", vpn_client=self.client))
        sm.current = "login"
        self.icon = os.path.join(os.path.dirname(__file__), '..', 'shared', 'logo.ico')
        return sm

    def on_stop(self):
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(LoginScreen(name="login", vpn_client=self.client))
        sm.add_widget(ServerSelectionScreen(name="server_selection", vpn_client=self.client))
        sm.add_widget(StatisticsScreen(name="statistics_screen", vpn_client=self.client))
        sm.current = "login"
        self.icon = os.path.join(os.path.dirname(__file__), '..', 'shared', 'logo.ico')
        # clean up the system proxy when the app closes
        logging.info("App closing, cleaning up...")

        try:
            self.client.remove_proxy()
        except Exception as e:
            logging.error(f"Cleanup error: {e}")


if __name__ == "__main__":
    VPNClientApp().run()
