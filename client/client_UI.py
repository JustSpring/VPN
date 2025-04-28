# VPN_CLIENT_UI.py

import time
import threading
import pyotp
import logging

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

import vpn_client  # your actual VPN client module

# configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# window size
Window.size = (400, 600)

# colors
PRIMARY_COLOR   = (0.2, 0.6, 0.86, 1)
SECONDARY_COLOR = (0.1, 0.1, 0.1, 1)
ACCENT_COLOR    = (0.95, 0.76, 0.26, 1)
TEXT_COLOR      = (1, 1, 1, 1)
ERROR_COLOR     = (0.8, 0.1, 0.1, 1)


class ModernWidget(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*SECONDARY_COLOR)
            self.bg_rect = RoundedRectangle(radius=[20], pos=self.pos, size=self.size)
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *args):
        self.bg_rect.pos  = self.pos
        self.bg_rect.size = self.size


class LoginScreen(Screen):
    def __init__(self, vpn_client, **kwargs):
        super().__init__(**kwargs)
        self.vpn_client = vpn_client

        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        title = Label(
            text="VPN Login", font_size=28,
            size_hint=(1, 0.15), color=TEXT_COLOR,
            halign="center", valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        input_container = BoxLayout(orientation="vertical", spacing=8, size_hint=(1, 0.55))

        self.ip_address = TextInput(
            hint_text="Server IP Address", text="192.168.68.129",
            font_size=16, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        input_container.add_widget(self.ip_address)

        self.username = TextInput(
            hint_text="Username", text="peleg",
            font_size=16, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        input_container.add_widget(self.username)

        self.password = TextInput(
            hint_text="Password", text="12345678",
            font_size=16, password=True, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        input_container.add_widget(self.password)

        totp = pyotp.TOTP("C2PJL3YGQVKAIDC5QJF7DYFPFTQ2QBET")
        self.totp = TextInput(
            hint_text="TOTP Code", text=totp.now(),
            font_size=16, multiline=False,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            foreground_color=TEXT_COLOR, padding=(10,10),
            size_hint=(1,None), height=35
        )
        input_container.add_widget(self.totp)

        layout.add_widget(input_container)

        login_button = Button(
            text="Login", font_size=18,
            size_hint=(1,0.07),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR, bold=True
        )
        login_button.bind(on_press=self.login)
        layout.add_widget(login_button)

        self.add_widget(layout)

    def login(self, _):
        ip       = self.ip_address.text.strip()
        user     = self.username.text.strip()
        pwd      = self.password.text.strip()
        totp_code= self.totp.text.strip()

        if not all([ip, user, pwd, totp_code]):
            return self.show_error("All fields are required.")

        try:
            res = self.vpn_client.get_certificates(user, pwd, totp_code, ip)
        except Exception as e:
            return self.show_error(str(e))

        if res == -1:
            return self.show_error("Invalid credentials or TOTP code.")

        # proceed to server selection
        threading.Thread(target=self.vpn_client.connect_to_control_server, daemon=True).start()
        time.sleep(0.5)
        sel = self.manager.get_screen('server_selection')
        sel.load_servers(self.vpn_client.proxy_list)
        self.manager.transition = SlideTransition(direction="left")
        self.manager.current = "server_selection"

    def show_error(self, msg):
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
    available_servers = ListProperty([])

    def __init__(self, vpn_client, **kwargs):
        super().__init__(**kwargs)
        self.vpn_client = vpn_client

        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        title = Label(
            text="MY VPN", font_size=24,
            size_hint=(1,0.15), color=TEXT_COLOR,
            halign="center", valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        self.server_spinner = Spinner(
            text='Choose a server', values=[],
            size_hint=(1,None), height=60, font_size=18,
            background_normal='', background_color=(0.2,0.2,0.2,1),
            color=TEXT_COLOR, padding=(10,10)
        )
        layout.add_widget(self.server_spinner)

        layout.add_widget(Widget(size_hint=(1,0.05)))

        connect_button = Button(
            text="Connect", font_size=18,
            size_hint=(1,0.07),
            background_normal='', background_color=ACCENT_COLOR,
            color=SECONDARY_COLOR, bold=True
        )
        connect_button.bind(on_press=self.connect)
        layout.add_widget(connect_button)

        self.add_widget(layout)

    def load_servers(self, server_list):
        self.available_servers = server_list
        if server_list:
            self.server_spinner.values = server_list
            self.server_spinner.text   = 'Choose a server'
        else:
            self.server_spinner.values = []
            self.server_spinner.text   = 'No servers available'

    def connect(self, _):
        sel = self.server_spinner.text
        if sel in ('Choose a server', ''):
            return self.show_error("Please select a server.")

        try:
            self.vpn_client.update_prefer_proxy(sel)
            time.sleep(1)
            threading.Thread(target=self.vpn_client.connect, daemon=True).start()
            self.show_info(f"Connected to {sel}.")
            self.manager.transition = SlideTransition(direction="left")
            self.manager.current    = "statistics_screen"
        except Exception as e:
            self.show_error(str(e))

    def show_error(self, msg):
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

    def show_info(self, msg):
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

        self.stats_label = Label(
            text="(Statistics will appear here...)", font_size=16,
            color=TEXT_COLOR
        )
        layout.add_widget(self.stats_label)

        shutdown_button = Button(
            text="Disconnect & Close", font_size=16,
            size_hint=(1,0.07),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR, bold=True
        )
        shutdown_button.bind(on_press=self.disconnect_and_close)
        layout.add_widget(shutdown_button)

        back_button = Button(
            text="Back to Server Selection", font_size=16,
            size_hint=(1,0.07),
            background_normal='', background_color=PRIMARY_COLOR,
            color=TEXT_COLOR, bold=True
        )
        back_button.bind(on_press=self.back_to_selection)
        layout.add_widget(back_button)

        self.add_widget(layout)

        # schedule stats updates
        Clock.schedule_interval(self.update_speed, 1)

    def update_speed(self, dt):
        # if kill flag set, stop the app
        if getattr(self.vpn_client, 'kill', False):
            logging.info("Kill flag detected, shutting down.")
            App.get_running_app().stop()
            return False  # unschedule further calls

        try:
            self.vpn_client.update(0)
            speed = self.vpn_client.calculate_speed()
            self.stats_label.text = f"Live Speed: {speed}"
        except Exception as e:
            self.stats_label.text = f"Error updating stats: {e}"
        # return True or None to keep scheduling

    def disconnect_and_close(self, _):
        # try:
        #     self.vpn_client.remove_proxy()
        # except Exception as e:
        #     logging.error(f"Error while disconnecting: {e}")
        App.get_running_app().stop()

    def back_to_selection(self, _):
        self.manager.transition = SlideTransition(direction="right")
        self.manager.current    = "server_selection"


class HomeScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = ModernWidget(orientation="vertical", padding=20, spacing=10)

        title = Label(
            text="Welcome to VPN", font_size=28,
            size_hint=(1,0.15), color=TEXT_COLOR,
            halign="center", valign="middle"
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        logout_button = Button(
            text="Logout", font_size=18,
            size_hint=(1,0.07),
            background_normal='', background_color=ERROR_COLOR,
            color=TEXT_COLOR, bold=True
        )
        logout_button.bind(on_press=lambda _: setattr(self.manager, 'current', 'login'))
        layout.add_widget(logout_button)

        self.add_widget(layout)


class VPNClientApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = vpn_client.Client()

    def build(self):
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(LoginScreen(name="login", vpn_client=self.client))
        sm.add_widget(ServerSelectionScreen(name="server_selection", vpn_client=self.client))
        sm.add_widget(StatisticsScreen(name="statistics_screen", vpn_client=self.client))
        sm.add_widget(HomeScreen(name="home"))

        # initial screen
        sm.current = "login"
        return sm

    def on_stop(self):
        logging.info("App closing, cleaning up...")
        try:
            self.client.remove_proxy()
        except Exception as e:
            logging.error(f"Cleanup error: {e}")


if __name__ == "__main__":
    VPNClientApp().run()
