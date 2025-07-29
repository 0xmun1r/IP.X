# setup.py
import os
from setuptools import setup, find_packages

setup(
    name='ip-x',
    version='0.0.1', # Ensure this matches your cli.py banner
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'dnspython',
        'shodan',
        'censys>=2.2.0', # Pinning version to ensure compatibility
        'requests',
        'colorama',
        # ipaddress is typically built-in, no need to list explicitly
    ],
    entry_points={
        'console_scripts': [
            'IP.X=ip_x.cli:main', # This creates the 'IP.X' command
        ],
    },
    author='0xmun1r',
    description='An origin IP finder behind WAF and CDN, with WAF detection capabilities.',
    long_description=open('README.md').read() if os.path.exists('README.md') else '',
    long_description_content_type='text/markdown',
    url='https://github.com/0xmun1r/IP.X', # Your GitHub URL
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License', # Or whatever license you use
        'Operating System :: OS Independent',
        'Topic :: Security',
        'Topic :: Internet',
        'Topic :: System :: Networking',
    ],
)
