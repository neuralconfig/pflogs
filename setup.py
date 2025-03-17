from setuptools import setup, find_packages

setup(
    name="pflogs",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "pandas",
        "pyarrow",
        "geoip2",
    ],
    extras_require={
        "dev": [
            "pytest",
            "black",
            "flake8",
            "mypy",
        ],
    },
)