import subprocess

process1 = subprocess.Popen(["python", "VPN_SERVER.py"]) # Create and launch process pop.py using python interpreter
process2 = subprocess.Popen(["python", "PROXY_SERVER.py"])

process1.wait() # Wait for process1 to finish (basically wait for script to finish)
process2.wait()
