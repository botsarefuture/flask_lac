from setuptools import setup, find_packages

setup(
    name="flask_lac",
    version="1.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Flask>=1.1.2",
        "Requests>=2.24.0",
        "Werkzeug>=1.0.1",
    ],
    author="Verso Vuorenmaa",
    author_email="verso@luova.club",
    description="A simple authentication package for Flask applications",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/botsarefuture/flask_lac",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
