import setuptools

try:
    from pyinstaller_setuptools import setup
except ImportError:
    print("WARNING: pyinstaller_setuptools not installed. You won't be able to `./setup.py pyinstaller`")
    from setuptools import setup


with open("README.md", "r") as f:
    long_description = f.read()

with open('requirements.txt') as f:
    install_requires = f.read()

setup(
    name='switch-mapper',

    entry_points={
        'console_scripts': [
            'switch-mapper = switchmapper.mapper:main',
        ],
    },
    data_files=[],

    version="0.1",
    author="Jarno Elonen",
    author_email="elonen@iki.fi",
    description="Recursive ethernet switch mapper using SNMP/LLDP",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elonen/switch-mapper",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
    platforms='any',
    install_requires=install_requires
)
