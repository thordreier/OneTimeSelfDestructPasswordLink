# One Time Self Destruct Password Link

Written in PHP.

## Install

Make sure Composer is installed - [check this link](https://getcomposer.org/download/)

```
cd /opt/
git clone https://github.com/thordreier/OneTimeSelfDestructPasswordLink.git

composer install

mkdir encrypted
chown www-data.www-data encrypted
chmod 700 encrypted

cp contrib/nginx.conf /etc/nginx/sites-available/onetimepassword
editor /etc/nginx/sites-available/onetimepassword
ln -s /etc/nginx/sites-available/onetimepassword /etc/nginx/sites-enabled/
systemctl reload nginx
```
