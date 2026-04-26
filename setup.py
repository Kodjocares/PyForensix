from setuptools import setup, find_packages

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='pyforensix',
    version='1.0.0',
    description='System Forensics & Intrusion Detection Toolkit',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='PyForensix Contributors',
    license='MIT',
    python_requires='>=3.8',
    packages=find_packages(),
    install_requires=[
        'psutil>=5.9.0',
    ],
    extras_require={
        'windows': ['pywin32>=306'],
        'enhanced': ['rich>=13.0', 'pandas>=2.0', 'openpyxl>=3.1'],
        'dev': ['pytest>=7.0', 'pytest-cov>=4.0', 'flake8>=6.0', 'mypy>=1.0'],
    },
    entry_points={
        'console_scripts': [
            'pyforensix=main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    keywords='forensics intrusion-detection security sysadmin incident-response',
)
