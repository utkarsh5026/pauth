from setuptools import find_packages, setup

setup(
    name="pauth",
    version="0.2.0",
    author="Utkarsh Priyadarshi",
    author_email="utkarshpriyadarshi5026@gmail.com",
    description="A Python library for handling OAuth 2.0 authentication with multiple providers.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/utkarsh5026/pauth",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    install_requires=[
        "requests",
    ],
    extras_require={
        "flask": ["Flask"],
        "django": ["Django"],
    },
    include_package_data=True,
)
