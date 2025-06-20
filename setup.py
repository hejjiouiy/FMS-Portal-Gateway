from setuptools import setup, find_packages

setup(
    name="keycloak_auth",
    version="0.1.0",
    packages=find_packages(include=["auth", "auth.*"]),
    install_requires=[
        "fastapi",
        "python-jose",
        "httpx",
    ],
    author="Your Name",
    description="Shared Keycloak auth logic for FastAPI microservices",
)
