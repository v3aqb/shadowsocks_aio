shadowsocks_aio
===============

shadowsocks_aio is a shadowsocks server built on top of ``asyncio``.

install
-------

::

    pip install https://github.com/v3aqb/shadowsocks_aio/archive/master.zip --process-dependency-links

update
------

::

    pip install https://github.com/v3aqb/shadowsocks_aio/archive/master.zip -U --process-dependency-links

configure example
-----------------

::

    servers:
        - ss://aes-128-cfb:password@0.0.0.0:8138
        - ss://aes-128-cfb:password@0.0.0.0:8139
    log_level: 20

usage
-----

::

    python -m shadowsocks_aio -c config.yaml
