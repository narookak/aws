server {
    listen      %ip%:%web_port%;
    server_name %domain_idn% %alias_idn%;
    root        %docroot%;
    index       index.php index.html index.htm;
    access_log  /var/log/nginx/domains/%domain%.log combined;
    access_log  /var/log/nginx/domains/%domain%.bytes bytes;
    error_log   /var/log/nginx/domains/%domain%.error.log error;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
        location ~* ^.+\.(jpeg|jpg|png|gif|bmp|ico|svg|css|js)$ {
            expires     max;
        }

        location ~ [^/]\.php(/|$) {
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            if (!-f $document_root$fastcgi_script_name) {
                return  404;
            }

            fastcgi_pass    %backend_lsnr%;
            fastcgi_index   index.php;
            fastcgi_buffers 64 256k;
            fastcgi_buffer_size 256k;
            include         /etc/nginx/fastcgi_params;
        }
    }
    
    location ~* "/\.(htaccess|htpasswd|env|user.ini)$" {
        deny    all;
        return  404;
    }

    include     /etc/nginx/conf.d/phpmyadmin.inc*;
}
