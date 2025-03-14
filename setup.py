# accumulate-python-client\setup.py 

from setuptools import setup, find_packages

setup(
    name="accumulate-python-client",
    version="0.1.1",
    description="Python SDK for Accumulate Blockchain API",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/opendlt/accumulate-python-client",
    author="JKG",
    author_email="jason@kompendium.co",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(include=["accumulate", "accumulate.*"]),
    python_requires=">=3.8",
    install_requires=[
        "ecdsa==0.18.0",
        "eth-keys==0.4.0",
        "pycryptodome==3.17.0",
        "websockets==10.4",
        "requests==2.31.0",
        "protobuf==4.24.3",
        "jsonschema==4.19.0",
        "msgpack==1.0.5",
        "croniter==1.4.1",
        "base58==2.1.1",
        "cryptography==44.0.0",
        "typing-extensions==4.7.1",
        "async-timeout==4.0.3",
        "pytest==7.4.0",
        "pytest-asyncio==0.21.0",
        "pytest-mock==3.11.1",
        "pytest-cov==4.1.0",
        "loguru==0.7.0",
    ],
    extras_require={
        "dev": ["pytest", "pytest-asyncio", "pytest-mock", "pytest-cov"],
    },
    entry_points={
        "console_scripts": [
            "accumulate-cli=accumulate.cli:main",
        ],
    },
)
