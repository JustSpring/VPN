import threading
import os
import sqlite3
import logging

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.graphics import Color, RoundedRectangle
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock

import VPN_SERVER  # your server module

# configure logging for UI actions
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Color palette
PRIMARY_COLOR = (0.2, 0.6, 0.86, 1)   # Blue
SECONDARY_COLOR = (0.1, 0.1, 0.1, 1)  # Dark background
TEXT_COLOR = (1, 1, 1, 1)            # White text

# Database file paths
LOG_DB_PATH = os.path.join(os.path.dirname(__file__), 'full_log.db')
USERS_DB_PATH = os.path.join(os.path.dirname(__file__), 'active_users.db')

# --- Start server backend threads ---
server = VPN_SERVER.Server()
server.create_ssl_context()
server.create_cert_context()
server.create_control_context()
server.find_all_proxy()
server.create_server_socket()
server.create_auth_server_socket()
server.create_control_socket()
threading.Thread(target=server.receive_clients_auth, daemon=True).start()
threading.Thread(target=server.receive_clients_control, daemon=True).start()
threading.Thread(target=server.receive_clients, daemon=True).start()

# Modern widget with rounded background
class ModernWidget(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*SECONDARY_COLOR)
            self.bg_rect = RoundedRectangle(radius=[20], pos=self.pos, size=self.size)
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size

class ServerControlScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = ModernWidget(orientation='vertical', padding=20, spacing=5)

        # Title
        title = Label(
            text='Server Control',
            font_size=24,
            size_hint=(1, 0.1),
            color=TEXT_COLOR,
            halign='center',
            valign='middle'
        )
        title.bind(size=title.setter('text_size'))
        layout.add_widget(title)

        # Active Users section
        au_label = Label(
            text='Active Users',
            font_size=20,
            size_hint=(1, 0.05),
            color=TEXT_COLOR,
            halign='left',
            valign='middle'
        )
        au_label.bind(size=au_label.setter('text_size'))
        layout.add_widget(au_label)

        # Header row for Active Users columns
        header = BoxLayout(
            orientation='horizontal',
            size_hint=(1, None),
            height=30,
            spacing=5
        )
        header.add_widget(Label(text='Name', size_hint_x=0.3, color=TEXT_COLOR, halign='left', valign='middle'))
        header.add_widget(Label(text='IP', size_hint_x=0.3, color=TEXT_COLOR, halign='left', valign='middle'))
        header.add_widget(Label(text='Proxy IP', size_hint_x=0.4, color=TEXT_COLOR, halign='left', valign='middle'))
        header.add_widget(Label(
            text='Action',
            size_hint_x=None,  # fixed width, just like your Kick button
            width=60,
            color=TEXT_COLOR,
            halign='center', valign='middle'
        ))
        for child in header.children:
            child.bind(size=lambda inst, w=child: setattr(inst, 'text_size', (inst.width, None)))
        layout.add_widget(header)

        self.active_list = GridLayout(cols=1, spacing=3, size_hint_y=None)
        self.active_list.bind(minimum_height=self.active_list.setter('height'))
        au_scroll = ScrollView(size_hint=(1, 0.2))
        au_scroll.add_widget(self.active_list)
        layout.add_widget(au_scroll)

        # Connected Proxies section
        cp_label = Label(
            text='Connected Proxies',
            font_size=20,
            size_hint=(1, 0.05),
            color=TEXT_COLOR,
            halign='left',
            valign='middle'
        )
        cp_label.bind(size=cp_label.setter('text_size'))
        layout.add_widget(cp_label)

        self.proxy_list = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.proxy_list.bind(minimum_height=self.proxy_list.setter('height'))
        proxy_scroll = ScrollView(size_hint=(1, 0.4))
        proxy_scroll.add_widget(self.proxy_list)
        layout.add_widget(proxy_scroll)

        # Refresh button
        btn = Button(
            text='Refresh',
            size_hint=(1, None),
            height=40,
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )
        btn.bind(on_press=lambda x: self.load_all())
        layout.add_widget(btn)

        # Last Opened Sites section
        logs_title = Label(
            text='Last Opened Sites',
            font_size=20,
            size_hint=(1, 0.05),
            color=TEXT_COLOR,
            halign='left',
            valign='middle'
        )
        logs_title.bind(size=logs_title.setter('text_size'))
        layout.add_widget(logs_title)

        self.logs_list = GridLayout(cols=1, spacing=3, size_hint_y=None)
        self.logs_list.bind(minimum_height=self.logs_list.setter('height'))
        logs_scroll = ScrollView(size_hint=(1, 0.3))
        logs_scroll.add_widget(self.logs_list)
        layout.add_widget(logs_scroll)

        self.add_widget(layout)

        # Initial load and periodic refresh
        Clock.schedule_once(lambda dt: self.load_all(), 0)
        Clock.schedule_interval(lambda dt: self.update_live(), 2)

    def load_all(self):
        self.load_active_users()
        self.load_proxies()
        self.load_logs()

    def update_live(self):
        self.load_active_users()
        self.load_logs()
        # proxies only on manual refresh

    def load_active_users(self):
        self.active_list.clear_widgets()
        try:
            conn = sqlite3.connect(USERS_DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT username, ip, proxy FROM active")
            for username, ip, proxy in cur.fetchall():
                # Row container
                row = BoxLayout(
                    orientation='horizontal',
                    size_hint_y=None,
                    height=30,
                    spacing=5
                )

                # User info
                lbl = Label(
                    text=username,
                    size_hint_x=0.3,
                    halign='left',
                    valign='middle',
                    color=TEXT_COLOR
                )
                lbl.bind(width=lambda inst, w: setattr(inst, 'text_size', (w, None)))
                row.add_widget(lbl)

                lbl_ip = Label(
                    text=ip,
                    size_hint_x=0.3,
                    halign='left',
                    valign='middle',
                    color=TEXT_COLOR
                )
                lbl_ip.bind(width=lambda inst, w: setattr(inst, 'text_size', (w, None)))
                row.add_widget(lbl_ip)

                lbl_proxy = Label(
                    text=proxy,
                    size_hint_x=0.4,
                    halign='left',
                    valign='middle',
                    color=TEXT_COLOR
                )
                lbl_proxy.bind(width=lambda inst, w: setattr(inst, 'text_size', (w, None)))
                row.add_widget(lbl_proxy)

                # Kick button
                btn = Button(
                    text='Kick',
                    size_hint=(None, None),
                    size=(60, 30),
                    background_normal='',
                    background_color=(1, 0, 0, 1),
                    color=TEXT_COLOR
                )
                btn.bind(on_press=lambda inst, ip=ip: self._on_kick(ip))
                row.add_widget(btn)

                self.active_list.add_widget(row)
            conn.close()
        except Exception as e:
            err = Label(
                text=f"Error loading users: {e}",
                size_hint_y=None,
                height=30,
                color=TEXT_COLOR
            )
            self.active_list.add_widget(err)

    def load_proxies(self):
        self.proxy_list.clear_widgets()
        server.find_all_proxy()
        for ip in server.proxy_list or []:
            lbl = Label(
                text=ip,
                size_hint_y=None,
                height=30,
                color=TEXT_COLOR
            )
            self.proxy_list.add_widget(lbl)

    def load_logs(self):
        self.logs_list.clear_widgets()
        try:
            conn = sqlite3.connect(LOG_DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT user, site FROM full_log ORDER BY time DESC LIMIT 20")
            for user, site in cur.fetchall():
                lbl = Label(
                    text=f'{user}    |    {site}',
                    size_hint_y=None,
                    height=30,
                    size_hint_x=1,
                    halign='left',
                    valign='middle',
                    color=TEXT_COLOR
                )
                lbl.bind(width=lambda inst, w: setattr(inst, 'text_size', (w, None)))
                self.logs_list.add_widget(lbl)
            conn.close()
        except Exception as e:
            err = Label(
                text=f"Error: {e}",
                size_hint_y=None,
                height=30,
                color=TEXT_COLOR
            )
            self.logs_list.add_widget(err)

    def _on_kick(self, ip):
        """Kick the client at given IP and refresh the list."""
        try:
            if server.kick(ip):
                logging.info(f"Kicked user at {ip}")
            else:
                logging.warning(f"No session found for IP {ip}")
        except Exception as e:
            logging.error(f"Error kicking {ip}: {e}")
        finally:
            self.load_active_users()

class ServerAdminApp(App):
    def build(self):
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(ServerControlScreen(name='main'))
        return sm

if __name__ == '__main__':
    ServerAdminApp().run()
