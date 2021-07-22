CloudflareDNS
========

Build
-----

    ./autogen.sh
    ./configure && make
    ./src/cfdns -c cfroute.txt -l /path/to/resolve.txt -s 8.8.8.8

Usage
-----

    -c CF_IPS_FILE        Cloudflare IP 段文件路径
    -l IPLIST_FILE        优选 IP 的文件路径，只读取第一个 IP
    -i BETTER_IP          优选 IP，如果指定了此参数，则忽略 -l 参数
    -b BIND_ADDR          监听地址默, 认: 0.0.0.0
    -p BIND_PORT          监听端口, 默认: 53
    -s DNS                上游 DNS 服务器, 默认: 8.8.8.8
    -v                    打印详细日志
    -h                    打印帮助信息并退出
    -V                    打印版本号并退出
