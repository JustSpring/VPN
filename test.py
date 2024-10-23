import winreg
INTERNET_SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
    r'Software\Microsoft\Windows\CurrentVersion\Internet Settings',
    0, winreg.KEY_ALL_ACCESS)

def set_key(name, value, type):
    winreg.SetValueEx(INTERNET_SETTINGS, name, 0, type, value)

set_key('ProxyEnable', 1, winreg.REG_DWORD)
set_key('ProxyServer', "127.0.0.1:8080", winreg.REG_SZ)
