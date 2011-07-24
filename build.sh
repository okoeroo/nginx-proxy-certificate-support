#!/bin/sh

./configure \
        --prefix=/usr \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --pid-path=/var/run/nginx/nginx.pid  \
        --lock-path=/var/lock/nginx.lock \
        --user=_www \
        --group=_www \
        --with-http_ssl_module \
        --with-http_flv_module \
        --with-http_gzip_static_module \
        --http-log-path=/var/log/nginx/access.log \
        --http-client-body-temp-path=/var/tmp/nginx/client/ \
        --http-proxy-temp-path=/var/tmp/nginx/proxy/ \
        --http-fastcgi-temp-path=/var/tmp/nginx/fcgi/ || exit 1

make || exit 1

sudo make install || exit 1

sudo nginx -s stop
sudo nginx
