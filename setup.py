from setuptools import setup, find_packages

setup(
    name="projectpop",
    version="2.0.0",
    description="Project Analyzer, Security Monitor & GitHub Publisher",
    author="Simon Peter Chappell",
    author_email="simonpetercys@gmail.com",
    url="https://github.com/Anesh2302/projectpop",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "projectpop=projectpop.cli:main",
        ],
    },
    install_requires=[],
    python_requires=">=3.8",
)
