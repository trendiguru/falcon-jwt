from setuptools import setup

with open('requirements.txt', encoding='utf-8') as reqs:
    INSTALL_REQUIRES = [l for l in reqs.read().split('\n')]

setup(name='falcon-jwt',
      version='1.0',
      description="Basic jwt support for falcon",
      url='https://github.com/trendiguru/falcon-jwt',
      py_modules=['falcon_jwt'],
      install_requires=INSTALL_REQUIRES,
     )
