from setuptools import setup, find_packages

setup(
    name="asphalt",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "click>=8.0.0",
        "scapy>=2.5.0",
    ],
    entry_points={
        "console_scripts": [
            "asphalt=asphalt_cli.main:cli",
        ],
    },
    # Add this to include non-Python files
    include_package_data=True,
    python_requires=">=3.8",
)