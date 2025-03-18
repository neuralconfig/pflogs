from setuptools import setup, find_packages

setup(
    name="pflogs",
    version="0.1.0",
    packages=find_packages() + ['scripts', 'tests'],
    install_requires=[
        "pandas",
        "pyarrow",
        "geoip2",
        "py-radix",  # For efficient CIDR range checking
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