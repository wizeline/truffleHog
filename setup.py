from setuptools import setup, find_packages

setup(
    name='truffleHogWize',
    version='2.0.92.1',
    description='Searches through git repositories for high entropy strings, digging deep into commit history.',
    url='https://github.com/dxa4481/truffleHog',
    author='Dylan Ayrey',
    author_email='dxa4481@rit.edu',
    license='GNU',
    packages = ['truffleHog'],
    install_requires=[
        'GitPython == 2.1.1',
        'truffleHogRegexes == 0.0.4'
    ],
    entry_points = {
      'console_scripts': ['trufflehog = truffleHog.truffleHog:main'],
    },
)
