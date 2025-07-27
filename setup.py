# setup.py

from setuptools import setup, find_packages

# Read the content of the README.md for the long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements from requirements.txt
with open("requirements.txt", "r") as f:
    install_requires = f.read().splitlines()

setup(
    name="ip_x", # This will be the name users install (pip install ip_x)
    version="0.1.0", # Start with a version number
    author="Your Name/Team Name", # <<< IMPORTANT: Replace with your name/team
    author_email="your.email@example.com", # <<< IMPORTANT: Replace with your email
    description="An origin IP finder behind WAF and CDN, with WAF detection capabilities.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/IP.X", # <<< IMPORTANT: Replace with your GitHub repository URL
    packages=find_packages(), # Automatically finds your 'ip_x' package directory
    install_requires=install_requires,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License", # Choose your license
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha", # Indicate development status
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet",
        "Topic :: System :: Networking",
    ],
    python_requires='>=3.7', # Minimum Python version required
    entry_points={
        'console_scripts': [
            'IP.X = ip_x.cli:main', # This creates the 'IP.X' command, pointing to main() in ip_x/cli.py
        ],
    },
)
