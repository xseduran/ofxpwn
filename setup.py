"""
OFXpwn - Open Financial Exchange Security Testing Framework
Setup configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="ofxpwn",
    version="1.0.0",
    author="Mike Piekarski",
    author_email="contact@breachcraft.io",
    description="A comprehensive penetration testing toolkit for OFX (Open Financial Exchange) servers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pect0ral/ofxpwn",
    project_urls={
        "Bug Tracker": "https://github.com/pect0ral/ofxpwn/issues",
        "Documentation": "https://github.com/pect0ral/ofxpwn/docs",
        "Source Code": "https://github.com/pect0ral/ofxpwn",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "PyYAML>=6.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "termcolor>=2.3.0",
        "rich>=13.0.0",
        "lxml>=4.9.0",
        "beautifulsoup4>=4.12.0",
        "tqdm>=4.66.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.1.0",
            "mypy>=1.5.0",
        ],
        "docs": [
            "mkdocs>=1.5.0",
            "mkdocs-material>=9.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ofxpwn=ofxpwn.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "ofxpwn": [
            "payloads/*.txt",
            "templates/*.yaml",
        ],
    },
    keywords="ofx security pentesting penetration-testing security-testing financial",
    license="MIT",
)
