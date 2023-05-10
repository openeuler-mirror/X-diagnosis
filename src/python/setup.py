from setuptools import setup, find_packages


setup(
    name="xdiagnose",
    version="1.0.1",
    description="System diagnostic tool set",
    url="https://gitee.com/openeuler/X-diagnosis",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    entry_points={
        'console_scripts': [
            'xdiag=xdiagnose.xdiagnose:main'
        ]
    },
)
