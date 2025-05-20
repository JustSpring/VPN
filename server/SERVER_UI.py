# server_UI.py
import threading
import os
import sqlite3
import logging
import pyotp
import qrcode
import base64
import manage_db
import vpn_server # Server logic
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.graphics import Color, RoundedRectangle
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.clock import Clock
from kivy.uix.image import Image
from kivy.core.image import Image as CoreImage
from kivy.uix.popup import Popup
from io import BytesIO

# set up basic logging for UI events
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# define color scheme
PRIMARY_COLOR = (0.2, 0.6, 0.86, 1)   # Blue
SECONDARY_COLOR = (0.1, 0.1, 0.1, 1)  # Dark background
TEXT_COLOR = (1, 1, 1, 1)            # White text

# Database file paths
LOG_DB_PATH = os.path.join(os.path.dirname(__file__), 'full_log.db')
ACTIVE_USERS_DB_PATH = os.path.join(os.path.dirname(__file__), 'active_users.db')
USERS_DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')



# launch starting actions on server back end
server = vpn_server.Server()
server.create_ssl_context()
server.create_auth_context()
server.create_control_context()
server.find_all_proxy()
server.create_server_socket()
server.create_auth_server_socket()
server.create_control_socket()

threading.Thread(target=manage_db.create, daemon=True).start()
threading.Thread(target=server.receive_clients_auth, daemon=True).start()
threading.Thread(target=server.receive_clients_control, daemon=True).start()
threading.Thread(target=server.receive_clients, daemon=True).start()


class ModernWidget(BoxLayout):
    """A Box Layout with a rounded, colored background."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(*SECONDARY_COLOR)
            self.bg_rect = RoundedRectangle(radius=[20], pos=self.pos, size=self.size)
        # keep the rect in sync with widget size&pos
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *args):
        self.bg_rect.pos = self.pos
        self.bg_rect.size = self.size


class ServerControlScreen(Screen):
    """Main control panel: users connected, proxies and recent history."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = ModernWidget(orientation='vertical', padding=20, spacing=5)

        # header label
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

        # button to switch to user management
        btn_manage = Button(
            text='Manage Users',
            size_hint=(1, None),
            height=40,
            background_normal='',
            background_color=PRIMARY_COLOR,
            color=TEXT_COLOR
        )
        btn_manage.bind(on_press=lambda inst: setattr(self.manager, 'current', 'user_control'))
        layout.add_widget(btn_manage)

        # section for active users

        au_label = Label(text='Active Users', font_size=20, size_hint=(1, 0.05), color=TEXT_COLOR, halign='left', valign='middle')
        au_label.bind(size=au_label.setter('text_size'))
        layout.add_widget(au_label)
        header = BoxLayout(orientation='horizontal', size_hint=(1, None), height=30, spacing=10)
        for text, ratio in [('Username', 0.3), ('IP', 0.2), ('Proxy', 0.3), ('Action', 0.2)]:
            lbl = Label(text=text, size_hint_x=ratio, color=TEXT_COLOR, halign='center', valign='middle')
            lbl.bind(size=lambda inst, w: setattr(inst, 'text_size', (inst.width, None)))
            header.add_widget(lbl)
        layout.add_widget(header)
        self.active_list = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.active_list.bind(minimum_height=self.active_list.setter('height'))
        au_scroll = ScrollView(size_hint=(1, 0.2), do_scroll_x=False, do_scroll_y=True)
        au_scroll.add_widget(self.active_list)
        layout.add_widget(au_scroll)

        # section for proxies
        cp_label = Label(text='Connected Proxies', font_size=20, size_hint=(1, 0.05), color=TEXT_COLOR, halign='left', valign='middle')
        cp_label.bind(size=cp_label.setter('text_size'))
        layout.add_widget(cp_label)
        self.proxy_list = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.proxy_list.bind(minimum_height=self.proxy_list.setter('height'))
        proxy_scroll = ScrollView(size_hint=(1, 0.2), do_scroll_x=False, do_scroll_y=True)
        proxy_scroll.add_widget(self.proxy_list)
        layout.add_widget(proxy_scroll)

        # section for history
        logs_label = Label(text='Last Opened Sites', font_size=20, size_hint=(1, 0.05), color=TEXT_COLOR, halign='left', valign='middle')
        logs_label.bind(size=logs_label.setter('text_size'))
        layout.add_widget(logs_label)
        self.logs_list = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.logs_list.bind(minimum_height=self.logs_list.setter('height'))
        logs_scroll = ScrollView(size_hint=(1, 0.3), do_scroll_x=False, do_scroll_y=True)
        logs_scroll.add_widget(self.logs_list)
        layout.add_widget(logs_scroll)

        # Refresh button
        btn_refresh = Button(text='Refresh All', size_hint=(1, None), height=40, background_normal='', background_color=PRIMARY_COLOR, color=TEXT_COLOR)
        btn_refresh.bind(on_press=lambda _: self.load_all())
        layout.add_widget(btn_refresh)

        self.add_widget(layout)

        # load data on start and refresh every 2 seconds
        Clock.schedule_once(lambda dt: self.load_all(), 0)
        Clock.schedule_interval(lambda dt: self.load_live(), 2)

    def load_all(self):
        """Fetch and display users, proxies, and history."""
        self.load_active_users()
        self.load_proxies()
        self.load_logs()

    def load_live(self):
        """update active users and history (proxies update on manual refresh)."""
        self.load_active_users()
        self.load_logs()

    def load_active_users(self):
        """Retrieve active connections from the DB."""
        self.active_list.clear_widgets()
        try:
            for username, ip, proxy in manage_db.get_active_users():
                if not proxy:
                    proxy = "None"
                row = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
                # show username, ip, proxy
                for text, ratio in [(username, 0.3), (ip, 0.2), (proxy or 'None', 0.3)]:
                    lbl = Label(text=text, size_hint_x=ratio, color=TEXT_COLOR)
                    lbl.bind(size=lambda inst, w: setattr(inst, 'text_size', (inst.width, None)))
                    row.add_widget(lbl)

                # kick button
                kick_btn = Button(text='Kick', size_hint_x=0.2, background_normal='', background_color=(1,0,0,1), color=TEXT_COLOR)
                kick_btn.bind(on_press=lambda inst, ip=ip: self.on_kick(ip))
                row.add_widget(kick_btn)
                self.active_list.add_widget(row)

        except Exception as e:
            # show error in UI
            err_lbl = Label(text=f"Error loading users: {e}", size_hint_y=None, height=30, color=(1,0,0,1))
            self.active_list.add_widget(err_lbl)

    def load_proxies(self):
        """List current proxy IPs."""
        self.proxy_list.clear_widgets()
        server.find_all_proxy()
        for ip in server.proxy_list or []:
            lbl = Label(text=ip, size_hint_y=None, height=30, color=TEXT_COLOR)
            lbl.bind(size=lambda inst, w: setattr(inst, 'text_size', (inst.width, None)))
            self.proxy_list.add_widget(lbl)

    def load_logs(self):
        """Fetch recent history (from DB)."""
        self.logs_list.clear_widgets()
        try:
            for user, site in manage_db.get_full_logging(20):
                lbl = Label(text=f"{user}    |    {site}", size_hint_y=None, height=30, color=TEXT_COLOR)
                lbl.bind(size=lambda inst, w: setattr(inst, 'text_size', (inst.width, None)))
                self.logs_list.add_widget(lbl)

        except Exception as e:
            err_lbl = Label(text=f"Error loading logs: {e}", size_hint_y=None, height=30, color=(1,0,0,1))
            self.logs_list.add_widget(err_lbl)

    def on_kick(self, ip):
        """Tell server to kick a client by IP."""
        try:
            if server.kick(ip):
                logging.info(f"Kicked user at {ip}")
            else:
                logging.warning(f"No session found for IP {ip}")
        except Exception as e:
            logging.error(f"Error kicking {ip}: {e}")
        finally:
            # Update active users after kicking the user
            self.load_active_users()


class UserManagementScreen(Screen):
    """Manage the users - add new ones, change details"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        layout = ModernWidget(orientation='vertical', padding=20, spacing=10)

        # title
        title = Label(text='User Management', font_size=24, size_hint=(1, None), height=50, color=TEXT_COLOR)
        layout.add_widget(title)

        # input boxes
        form = GridLayout(cols=2, row_force_default=True, row_default_height=40, spacing=20)
        form.add_widget(Label(text='Username:', color=TEXT_COLOR))
        self.input_username = TextInput(multiline=False)
        form.add_widget(self.input_username)
        form.add_widget(Label(text='Password:', color=TEXT_COLOR))
        self.input_password = TextInput(multiline=False)
        form.add_widget(self.input_password)
        form.add_widget(Label(text='TOTP Key (hex):', color=TEXT_COLOR))
        self.input_totp = TextInput(multiline=False)
        form.add_widget(self.input_totp)
        layout.add_widget(form)

        # action buttons
        btn_box = BoxLayout(size_hint=(1, None), height=50, spacing=10)
        add_btn = Button(text='Add User', background_normal='', background_color=PRIMARY_COLOR, color=TEXT_COLOR)
        add_btn.bind(on_press=self.add_user)
        btn_box.add_widget(add_btn)
        upd_btn = Button(text='Update User', background_normal='', background_color=PRIMARY_COLOR, color=TEXT_COLOR)
        upd_btn.bind(on_press=self.update_user)
        btn_box.add_widget(upd_btn)
        del_btn = Button(text='Delete User', background_normal='', background_color=(1,0,0,1), color=TEXT_COLOR)
        del_btn.bind(on_press=self.delete_user)
        btn_box.add_widget(del_btn)
        layout.add_widget(btn_box)

        # list of registered users
        ru_lbl = Label(text='Registered Users', font_size=20, size_hint=(1, None), height=30, color=TEXT_COLOR, halign='left', valign='middle')
        ru_lbl.bind(size=ru_lbl.setter('text_size'))
        layout.add_widget(ru_lbl)
        self.user_list = GridLayout(cols=1, spacing=5, size_hint_y=None)
        self.user_list.bind(minimum_height=self.user_list.setter('height'))
        user_scroll = ScrollView(size_hint=(1, 0.5), do_scroll_x=False, do_scroll_y=True)
        user_scroll.add_widget(self.user_list)
        layout.add_widget(user_scroll)

        # back button (back to main screen)
        back_btn = Button(text='Back', size_hint=(1, None), height=40, background_normal='', background_color=SECONDARY_COLOR, color=TEXT_COLOR)
        back_btn.bind(on_press=lambda inst: setattr(self.manager, 'current', 'main'))
        layout.add_widget(back_btn)

        self.add_widget(layout)
        self.load_users()

    def load_users(self):
        self.user_list.clear_widgets()
        try:
            header = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=20)
            for text, width in [('Username', 0.3), ('Password', 0.3), ('TOTP Key (hex)', 0.4)]:
                lbl = Label(text=text, size_hint_x=width, color=TEXT_COLOR, bold=True)
                lbl.bind(size=lambda inst, w: setattr(inst, 'text_size', (inst.width, None)))
                header.add_widget(lbl)
            self.user_list.add_widget(header)
            for username, password, totpKey in manage_db.get_all_users():
                # add '...' if too long
                display_pass = (password[:17] + '...') if len(password) > 20 else password
                display_totp = totpKey.hex()[:17] + '...' if isinstance(totpKey, (bytes, str)) else 'None'

                row = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=20)
                for text, ratio in [(username, 0.3), (display_pass, 0.3), (display_totp, 0.4)]:
                    lbl = Label(text=text, size_hint_x=ratio, color=TEXT_COLOR)
                    lbl.bind(size=lambda inst, w: setattr(inst, 'text_size', (inst.width, None)))
                    row.add_widget(lbl)
                self.user_list.add_widget(row)

        except Exception as e:
            err = Label(text=f"Error loading registered users: {e}", size_hint_y=None, height=30, color=(1,0,0,1))
            self.user_list.add_widget(err)

    def show_error(self, msg):
        """Popup for input validation errors."""
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

    def is_hex(self, s):
        """Helper function for add_user"""
        if not isinstance(s, str):
            return False
        try:
            int(s, 16)
            return True
        except ValueError:
            return False

    def add_user(self, _):
        """add a new user"""
        # require at least username and password
        if not self.input_username.text.strip() or not self.input_password.text.strip():
            return self.show_error("Username and password are required.")
        if self.input_username.text.strip() in [user[0] for user in manage_db.get_all_users()]:
            return self.show_error("Username not available.")
        try:
            # Generate TOTP if black
            if self.input_totp.text.strip() == "":
                print("")
                totp = pyotp.random_base32()
                self.input_totp.text = base64.b32decode(totp).hex()
            else:
                if not self.is_hex(self.input_totp.text.strip()):
                    return self.show_error("Totp secret needs to be in hex.")
                totp = self.input_totp.text.strip()

            manage_db.add_user(self.input_username.text, self.input_password.text, totp,"")
            logging.info(f"Added user {self.input_username.text}")
            # Update users list
            self.load_users()
            self.show_qr_code(totp)
        except Exception as e:
            logging.error(f"Error adding user: {e}")


    def show_qr_code(self, totp_key):
        """Show QR code for TOTP"""
        # Put the TOTP key in the right format for a TOTP url
        try:
            uri = pyotp.totp.TOTP(totp_key).provisioning_uri(name=self.input_username.text, issuer_name="SpringConnect")
            qr = qrcode.make(uri)
            buffer = BytesIO()
            qr.save(buffer, format='PNG')
            buffer.seek(0)
            img = CoreImage(buffer, ext='png')

            popup_layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
            popup_layout.add_widget(Image(texture=img.texture, size_hint=(1, 0.9)))
            btn = Button(text='Close', size_hint=(1, 0.1))
            popup_layout.add_widget(btn)

            popup = Popup(title='TOTP QR Code', content=popup_layout, size_hint=(0.8, 0.8))
            btn.bind(on_press=popup.dismiss)
            popup.open()
        except Exception as e:
            logging.error(f"Failed to display QR code: {e}")

    def update_user(self, _):
        """Update user identified by username"""
        try:
            if not self.input_username.text.strip() :
                return self.show_error("Username is required.")
            if not self.input_password.text.strip() and not self.input_totp.text:
                return self.show_error("password or totp are required.")
            if self.input_totp.text and not self.is_hex(self.input_totp.text):
                return self.show_error("Totp secret needs to be in hex.")
            if self.input_username.text.strip() not in [user[0] for user in manage_db.get_all_users()]:
                return self.show_error("Username not found.")
            totp_bytes = bytes.fromhex(self.input_totp.text)
            manage_db.update_user(self.input_username.text,self.input_password.text,totp_bytes)
            logging.info(f"Updated user {self.input_username.text}")
            self.load_users()
        except Exception as e:
            logging.error(f"Error updating user: {e}")

    def delete_user(self, _):
        """Update user identified by username"""
        try:
            if not manage_db.delete_user(self.input_username.text):
                return self.show_error("Username received not found.")
            else:
                logging.info(f"Deleted user {self.input_username.text}")
                self.load_users()
        except Exception as e:
            logging.error(f"Error deleting user: {e}")
            return self.show_error("Username received not found.")



class ServerAdminApp(App):
    # Basic settings (name & logo)
    def build(self):
        self.icon = os.path.join(os.path.dirname(__file__), '..', 'shared', 'logo.ico')
        self.title = 'SpringConnect Admin Panel'
        sm = ScreenManager(transition=SlideTransition())
        sm.add_widget(ServerControlScreen(name='main'))
        sm.add_widget(UserManagementScreen(name='user_control'))
        return sm


if __name__ == '__main__':
    ServerAdminApp().run()
