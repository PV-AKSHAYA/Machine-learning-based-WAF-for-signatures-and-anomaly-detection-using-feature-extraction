# setup.py

from setuptools import setup, find_packages

setup(
    name="ml_waf_project",
    version="0.1.0",
    description="Hybrid ML-drivenAF plugin package",
    author="Your Name",
    author_email="you@example.com",
    url="https://github.com/yourusername/ml_waf_project",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[
        "proxy.py>=2.0",
        "scikit-learn>=1.0",
        "joblib>=1.2",
        "flask>=2.0",
        "pandas>=1.3",
        "plotly>=5.0",
    ],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "run-ml-waf=main_waf_server:main",
        ],
    },
)
