# setup.py
from setuptools import setup, find_packages

setup(
    name="aws-security-scanner",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.26.0",
        "pyyaml>=6.0",
        "jsonschema>=4.17.0",
        "pandas>=1.5.0",
        "plotly>=5.13.0",
        "jinja2>=3.1.0",
        "dataclasses-json>=0.5.7",
    ],
    python_requires=">=3.8",
    author="Your Name",
    author_email="your.email@example.com",
    description="AWS Security Scanner for identifying exposed resources",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/aws-security-scanner",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
    ],
)
