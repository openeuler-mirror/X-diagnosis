from setuptools import setup, find_packages


setup(
    name="xdiagnose",
    version="1.0",
    author="euleros_maintain",
    author_email="maintain.euleros@huawei.com",
    description="Diagnose euleros system tool",
    url="http://maintain.euleros.huawei.com",
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
