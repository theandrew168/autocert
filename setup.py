from setuptools import setup

with open('README.md') as f:
    readme = f.read()

setup(
    name='autocert',
    version='0.0.1',
    author='Andrew Dailey',
    description='Automatic TLS cert acquisition and renewal for Python web apps',
    long_description=readme,
    long_description_content_type='text/markdown',
    url='https://github.com/theandrew168/autocert',
    packages=[],
    py_modules=['autocert'],
    install_requires=[],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ],
    python_requires='>=3.0',
)
