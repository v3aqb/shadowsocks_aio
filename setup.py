from setuptools import setup, find_packages

long_description = 'shadowsocks server with asyncio'

setup(
    name="shadowsocks_aio",
    version="0.0.1",
    license='http://www.apache.org/licenses/LICENSE-2.0',
    description="A fast tunnel proxy that help you get through firewalls",
    author='v3aqb',
    author_email='null',
    url='https://github.com/v3aqb/shadowsocks_aio',
    packages=find_packages(),
    package_data={
        'shadowsocks_aio': ['README.rst', 'LICENSE']
    },
    dependency_links=['https://github.com/v3aqb/hxcrypto/archive/master.zip#egg=hxcrypto-0.0.1'],
    install_requires=["hxcrypto", "pyyaml"],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: Proxy Servers',
    ],
    long_description=long_description,
)
