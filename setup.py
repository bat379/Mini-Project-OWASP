"""
setup.py — Makes the scanner pip-installable as a CLI tool.

Install:
  pip install .            # installs 'portscan' command globally
  pip install -e .         # editable/dev install

Then use:
  portscan --target scanme.nmap.org --ports 1-100
"""

from setuptools import setup, find_packages

setup(
    name="smart-port-scanner",
    version="2.0.0",
    author="Your Name",
    description="Multithreaded/async port scanner with banner grabbing, "
                "fingerprinting, vulnerability detection, and HTML reports.",
    long_description=open("README.md", encoding="utf-8").read()
    if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    packages=find_packages(exclude=["tests*"]),
    entry_points={
        "console_scripts": [
            "portscan = scanner:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
    ],
    keywords=["port scanner", "network security", "banner grabbing",
              "vulnerability scanner", "ethical hacking", "cybersecurity"],
)
