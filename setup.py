from setuptools import setup

with open('README.md') as f:
    readme = f.read()

setup(
    name='autocert',
    version='0.0.6',
    author='Andrew Dailey',
    description='Automatic TLS cert issuance and renewal for Python web apps',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/theandrew168/autocert',
    packages=['autocert'],
    install_requires=[
        'appdirs',
        'cryptography',
        'requests',
    ],
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: System :: Networking',
    ],
    python_requires='>=3.0',
)
