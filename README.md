# One Time Self Destruct Password Link

Written in PHP.

## Install

Make sure Composer is installed - [check this link](https://getcomposer.org/download/)

```
cd /opt/
git clone https://github.com/thordreier/OneTimeSelfDestructPasswordLink.git

composer install

dd if=/dev/random bs=1 count=96 | base64 -w 0 > secret
chown www-data.www-data secret
chmod 400 secret

mkdir password
chown www-data.www-data password
chmod 700 password

cp contrib/nginx.conf /etc/nginx/sites-available/onetimepassword
editor /etc/nginx/sites-available/onetimepassword
ln -s /etc/nginx/sites-available/onetimepassword /etc/nginx/sites-enabled/
systemctl reload nginx
```
