#!/bin/bash -v

RETRY=0
USER="webapps"
DOMAINNAME="example.com"
WEBALIAS=""
WEBROOT="/home/${USER}_web/web/$DOMAINNAME/public_html"
DB_HOST="localhost"
blowfish_secret=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c72)
#MySQL root user password
mypass=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c16)
#Password for db user
DBPASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c16)
#User password
USER_PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c16)
arch=$(uname -i)
os='ubuntu'
release="$(lsb_release -s -r)"
codename="$(lsb_release -s -c)"
#SFTP Port
SFTP_PORT=7272
#SHELL Colors
RED='\033[0;31m'
NC='\033[0m' # No Color
PMA_VERSION="4.8.3"
MODSECURITY="Yes"
#Find PHP Version installed
PHP_VERSION="7.0"
NODEJS_ENABLED="Yes"
#GITHub repo URL
giturl="https://raw.githubusercontent.com/narookak/aws/master"
# Defining return code check function
check_result() {
    if [ $1 -ne 0 ]; then
        echo "Error: $2"
        exit $1
    fi
}
# Checking root permissions
if [ "x$(id -u)" != 'x0' ]; then
    check_result 1 "Script can be run executed only by root"
fi
# Checking wget
if [ ! -e '/usr/bin/wget' ]; then
    apt-get -y install wget
    check_result $? "Can't install wget"
fi

# setup APT to run interactively
export DEBIAN_FRONTEND=noninteractive
#Add mariadb repo

apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
add-apt-repository -y "deb [arch=amd64,arm64,i386,ppc64el] http://nyc2.mirrors.digitalocean.com/mariadb/repo/10.2/ubuntu $codename main"

# Checking universe repository
if [[ ${release:0:2} -gt 16 ]]; then
    if [ -z "$(grep universe /etc/apt/sources.list)" ]; then
        add-apt-repository -y universe
    fi
fi

# Installing nginx repo
apt=/etc/apt/sources.list.d
echo "deb http://nginx.org/packages/ubuntu/ $codename nginx" \
    > $apt/nginx.list
wget http://nginx.org/keys/nginx_signing.key -O /tmp/nginx_signing.key
apt-key add /tmp/nginx_signing.key

if [[ ${PHP_VERSION} == 5.6 ]]; then
    add-apt-repository -y ppa:ondrej/php
    packages="debconf-utils wget curl nginx php5.6-fpm php5.6-dev php-pear php5.6-mysql php5.6-mcrypt php5.6-mbstring php5.6-gd php5.6-curl php5.6-zip unzip libmcrypt-dev wget mariadb-server mariadb-client-core-10.2 sendmail-bin libwww-perl"
    else
    packages="debconf-utils wget curl nginx php-fpm php-dev php-pear php-mysql php-mbstring php-gd php-curl php-zip unzip libmcrypt-dev wget mariadb-server mariadb-client-core-10.2 sendmail-bin libwww-perl"

fi

if [[ ${MODSECURITY} == "Yes" ]]; then
    echo "Installing additional packages for mod_security"
    packages="$packages apt-utils autoconf automake build-essential git libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev"
fi

if [[ ${NODEJS_ENABLED} == "Yes" ]]; then
    echo "Enable nodejs repo to install additional packages for nodejs"
	curl -sL https://deb.nodesource.com/setup_9.x  | sudo -E bash -
    packages="$packages nodejs"
fi

#install required packages and update system
apt update
apt-get install -y software-properties-common
apt install -y ${packages}
#apt upgrade -y

# Configuring MySQL/MariaDB
service mysql restart > /dev/null 2>&1

#Securing MySQL/MariaDB installation
mysqladmin -u root password $mypass
echo -e "[client]\npassword='$mypass'\n" > /root/.my.cnf
chmod 600 /root/.my.cnf
mysql -e "DELETE FROM mysql.user WHERE User=''"
mysql -e "DROP DATABASE test" >/dev/null 2>&1
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
mysql -e "DELETE FROM mysql.user WHERE user='' OR password='';"
mysql -e "FLUSH PRIVILEGES"

#Re-configure nginx config
wget $giturl/nginx/nginx.conf -O /etc/nginx/nginx.conf
 sed -i "/%cidr_block%/d" /etc/nginx/nginx.conf

#Install php-mycrypt extension
if [[ ${PHP_VERSION} > 7 ]]; then
    echo -ne '\n' |pecl install mcrypt-1.0.1
    echo "extension=mcrypt.so" > /etc/php/${PHP_VERSION}/mods-available/mcrypt.ini
    phpenmod mcrypt
fi

#Install PHPMyAdmin and configure nginx
wget $giturl/nginx/phpmyadmin.inc -O /etc/nginx/conf.d/phpmyadmin.inc
wget https://files.phpmyadmin.net/phpMyAdmin/${PMA_VERSION}/phpMyAdmin-${PMA_VERSION}-english.zip -O /tmp/phpMyAdmin-${PMA_VERSION}-english.zip
cd /tmp
unzip phpMyAdmin-${PMA_VERSION}-english.zip
mv phpMyAdmin-${PMA_VERSION}-english /usr/share/myadminx

sed -i 's%phpmyadmin%myadminx%' /etc/nginx/conf.d/phpmyadmin.inc
sed -i "s%fastcgi_pass 127.0.0.1:9000;%fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;%" /etc/nginx/conf.d/phpmyadmin.inc
cp /usr/share/myadminx/config.sample.inc.php /usr/share/myadminx/config.inc.php
sed -i "s/\['host'\] = 'localhost'/\['host'\] = \'"${DB_HOST}"\'/" /usr/share/myadminx/config.inc.php
sed -i "s/\['blowfish_secret'\] = ''/\['blowfish_secret'\] = \'${blowfish_secret}\'/" /usr/share/myadminx/config.inc.php

# Setup website and re-configure nginx
wget $giturl/web/templates/laravel.tpl -O /etc/nginx/conf.d/$DOMAINNAME.conf
wget $giturl/php-fpm/www-pool.conf -O /etc/php/${PHP_VERSION}/fpm/pool.d/$DOMAINNAME.conf
useradd -m ${USER}_web
echo ${USER}_web:${USER_PASS} | chpasswd
mkdir -p $WEBROOT
mkdir -p /home/${USER}_web/tmp
echo "<?php phpinfo();" > $WEBROOT/index.php
wget $giturl/php-fpm/.user.ini -O $WEBROOT/.user.ini
chown ${USER}_web.${USER}_web -R /home/${USER}_web
sed -i 's/%ip%:%web_port%;/80;/' /etc/nginx/conf.d/$DOMAINNAME.conf
sed -i "s/%domain_idn%/$DOMAINNAME/" /etc/nginx/conf.d/$DOMAINNAME.conf
sed -i "s/%alias_idn%/$WEBALIAS/" /etc/nginx/conf.d/$DOMAINNAME.conf
sed -i "s@%docroot%@/home/${USER}_web/web/$DOMAINNAME/public_html@" /etc/nginx/conf.d/$DOMAINNAME.conf
sed -i "s@%backend_lsnr%@unix:/var/run/php/$DOMAINNAME.sock@" /etc/nginx/conf.d/$DOMAINNAME.conf
sed -i "s/%domain%/$DOMAINNAME/" /etc/nginx/conf.d/$DOMAINNAME.conf

#update php-fpm pool for website
sed -i "s/%backend%/$DOMAINNAME/" /etc/php/${PHP_VERSION}/fpm/pool.d/$DOMAINNAME.conf
sed -i "s/%user%/${USER}_web/" /etc/php/${PHP_VERSION}/fpm/pool.d/$DOMAINNAME.conf

#Create DB and User for website
mysql -e "CREATE DATABASE ${USER}_db CHARACTER SET utf8 COLLATE utf8_general_ci;"
mysql -e "CREATE USER ${USER}_usr@localhost IDENTIFIED BY '${DBPASS}';"
mysql -e "GRANT ALL PRIVILEGES ON ${USER}_db.* TO '${USER}_usr'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# install and configure mod_security
if [[ ${MODSECURITY} == "Yes" ]]; then

#Install mod_security
mkdir /opt/ModSecurity && cd /opt/ModSecurity
   git clone -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity . && \
   git submodule init && \
   git submodule update && \
   ./build.sh && \
   ./configure && make && make install
   
# install nginx connector
NGINX_VERSION="$(nginx -v 2>&1 | awk -F/ '{print $2}')"
cd  /opt
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git && \
    wget http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz && \
    tar -zxvf nginx-$NGINX_VERSION.tar.gz
	
cd /opt/nginx-$NGINX_VERSION
  ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx && \
    make modules && \
    cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules
	sed -i '/pid/a load_module modules/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf

#create folder named modsec under nginx
mkdir /etc/nginx/modsec
   cp /opt/ModSecurity/unicode.mapping /etc/nginx/modsec/
   cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf

# install owasp ruleset
cd /opt
git clone -b v3.0/master https://github.com/SpiderLabs/owasp-modsecurity-crs
cd owasp-modsecurity-crs
cp crs-setup.conf.example crs-setup.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
cat > /etc/nginx/modsec/main.conf <<EOF
# From https://github.com/SpiderLabs/ModSecurity/blob/master/
# modsecurity.conf-recommended
#
# Edit to set SecRuleEngine On
Include "/etc/nginx/modsec/modsecurity.conf"
Include "/opt/owasp-modsecurity-crs/crs-setup.conf"
Include "/opt/owasp-modsecurity-crs/rules/*.conf"
EOF

sed -i '/error_log/a modsecurity_rules_file /etc/nginx/modsec/main.conf;' /etc/nginx/conf.d/$DOMAINNAME.conf
sed -i '/error_log/a modsecurity on;' /etc/nginx/conf.d/$DOMAINNAME.conf
fi
# disable nginx auto update
    apt-mark hold nginx
	
## end of mod_security config

if [[ ${NODEJS_ENABLED} == "Yes" ]]; then
    echo "install pm2 packages for nodejs"
	/usr/bin/npm install -g pm2
fi

#restart services
mkdir -p /var/log/nginx/domains
systemctl restart php${PHP_VERSION}-fpm && systemctl restart nginx
echo -e "Changing SSH Port, Please update the firewall rules and restart server or SSH service"
echo -e "${RED}DO NOT CLOSE THE CURRENT SSH SESSION, VERIFY SSH CONNECTIVITY IN ANOTHER SESSION${NC}"
sed -i "s/^#Port 22/Port ${SFTP_PORT}/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port ${SFTP_PORT}/" /etc/ssh/sshd_config

echo -e "\n-----------------------------\n"
echo -e "mysql root password: ${mypass} \r"
echo -e "SFTP Hostname: $(curl -s https://api.ipify.org) \r"
echo -e "SFTP Username: ${USER}_web \r"
echo -e "SFTP Password: ${USER_PASS} \r"
echo -e "SFTP Port: ${SFTP_PORT} \r"
echo -e "PHPMyAdmin URL: http(s)://$(curl -s https://api.ipify.org)/myadminx \r"
echo -e "DBNAME: ${USER}_db \r"
echo -e "DBUSER: ${USER}_usr \r"
echo -e "DBPASS: ${DBPASS} \r"
echo -e "DBHOST: ${DB_HOST} \r"
echo -e "\n-----------------------------\n"
