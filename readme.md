# mod_redsec_terminator

Apache module CRS

## Install Apache

https://httpd.apache.org/

## Install Lib JSON C

https://github.com/json-c/json-c

## Setup VHost

```httpd
<VirtualHost *:8282>
    ServerAdmin webmaster@yourdomain.com
    DocumentRoot "/Users/janitrasatria/Development/www"
    ServerName yourdomain.com

    <Directory "/Users/janitrasatria/Development/www">
      Options Indexes FollowSymLinks
      AllowOverride All
      Require all granted
    </Directory>

    LoadModule mod_redsec_module modules/mod_hello.so

    # Test handler
    <Location "/test">
        SetHandler mod_redsec_terminator
    </Location>

    #ErrorLog ${APACHE_LOG_DIR}/your-site-error.log
    #CustomLog ${APACHE_LOG_DIR}/your-site-access.log combined
</VirtualHost>
```

## Run Apache Mod

```sh
make
```
