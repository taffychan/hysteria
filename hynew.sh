#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN='\033[0m'

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
PACKAGE_UPDATE=("apt-get -y update" "apt-get -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')") 

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ $EUID -ne 0 ]] && red "注意：请在root用户下运行脚本" && exit 1

check_ip(){
    IP=$(curl -s6m8 ip.gs) || IP=$(curl -s4m8 ip.gs)

    if [[ -n $(echo $IP | grep ":") ]]; then
        IP="[$IP]"
        RIP=64
    else
        RIP=46
    fi
}

check_tun(){
    vpsvirt=$(systemd-detect-virt)
    main=`uname  -r | awk -F . '{print $1}'`
    minor=`uname -r | awk -F . '{print $2}'`
    TUN=$(cat /dev/net/tun 2>&1 | tr '[:upper:]' '[:lower:]')
    if [[ ! $TUN =~ "in bad state"|"处于错误状态"|"ist in schlechter Verfassung" ]]; then
        if [[ $vpsvirt == lxc ]]; then
            if [[ $main -lt 5 ]] || [[ $minor -lt 6 ]]; then
                red "检测到未开启TUN模块, 请到VPS厂商的控制面板处开启"
                exit 1
            else
                return 0
            fi
        elif [[ $vpsvirt == "openvz" ]]; then
            wget -N --no-check-certificate https://raw.githubusercontents.com/taffychan/warp/main/tun.sh && bash tun.sh
        else
            red "检测到未开启TUN模块, 请到VPS厂商的控制面板处开启"
            exit 1
        fi
    fi
}

archAffix(){
    case "$(uname -m)" in
        i686 | i386) echo '386' ;;
        x86_64 | amd64) echo 'amd64' ;;
        armv5tel) echo 'arm-5' ;;
        armv7 | armv7l) echo 'arm-7' ;;
        armv8 | arm64 | aarch64) echo 'arm64' ;;
        s390x) echo 's390x' ;;
        *) red " 不支持的CPU架构！" && exit 1 ;;
    esac
    return 0
}

install_base() {
    if [[ $SYSTEM != "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} wget curl sudo python3
}

downloadHysteria() {
    rm -f /usr/local/bin/hysteria
    rm -rf /etc/hysteria /root/acl
    mkdir /etc/hysteria
    last_version=$(curl -Ls "https://api.github.com/repos/HyNetwork/Hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || last_version=v$(curl -Ls "https://data.jsdelivr.com/v1/package/resolve/gh/HyNetwork/Hysteria" | grep '"version":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z $last_version ]]; then
        red "检测 Hysteria 版本失败，可能是网络问题，请稍后再试"
        exit 1
    fi
    yellow "检测到 Hysteria 最新版本：${last_version}，开始安装"
    wget -N --no-check-certificate https://github.com/HyNetwork/Hysteria/releases/download/${last_version}/Hysteria-tun-linux-$(archAffix) -O /usr/local/bin/hysteria
    if [[ $? -ne 0 ]]; then
        red "下载 Hysteria 失败，请确保你的服务器能够连接并下载 Github 的文件"
        exit 1
    fi
    chmod +x /usr/local/bin/hysteria
}

makeConfig() {
    mkdir /root/acl
    read -rp "请输入 Hysteria 的连接端口 [默认随机生成]: " PORT
    [[ -z $PORT ]] && PORT=$(shuf -i 1000-65535 -n 1)
    if [[ -n $(ss -ntlp | awk '{print $4}' | grep -w "$PORT") ]]; then
        until [[ -z $(ss -ntlp | awk '{print $4}' | grep -w "$PORT") ]]; do
            if [[ -n $(ss -ntlp | awk '{print $4}' | grep -w "$PORT") ]]; then
                yellow "你设置的端口目前已被其他程序占用，请重新设置一个新的端口"
                read -rp "请输入 Hysteria 的连接端口 [默认随机生成]: " PORT
                [[ -z $PORT ]] && PORT=$(shuf -i 1000-65535 -n 1)
            fi
        done
    fi
    read -rp "请输入 Hysteria 的连接混淆密码 [默认随机生成]: " OBFS
    [[ -z $OBFS ]] && OBFS=$(date +%s%N | md5sum | cut -c 1-32)
    yellow "正在生成配置文件，请稍等..."
    sleep 2
    sysctl -w net.core.rmem_max=4000000
    ulimit -n 1048576 && ulimit -u unlimited
    openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
    openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.baidu.com"
    cat <<EOF > /etc/hysteria/config.json
{
    "listen": ":${PORT}",
    "resolve_preference": "${RIP}",
    "cert": "/etc/hysteria/cert.crt",
    "key": "/etc/hysteria/private.key",
    "obfs": "${OBFS}"
}
EOF
    cat <<EOF > /root/hy-client.json
{
    "server": "${IP}:${PORT}",
    "obfs": "${OBFS}",
    "up_mbps": 1000,
    "down_mbps": 1000,
    "insecure": true,
    "socks5": {
        "listen": "127.0.0.1:1080",
        "timeout" : 300,
        "disable_udp": false
    },
    "http": {
        "listen": "127.0.0.1:1081",
        "timeout" : 300,
        "disable_udp": false
    }
}
EOF
    cat <<EOF > /root/hy-clash.yaml
proxies:
 - name: Hysteria
   type: hysteria
   server: "${IP}"
   port: 24321
   obfs: 68aadf1ba73819**********
   protocol: udp
   up: 20 #默认为Mbps
   down: 100
   skip-cert-verify: true
EOF
    cd /root/acl
    wget -N https://raw.githubusercontent.com/taffychan/hysteria/main/GetRoutes.py
    python3 GetRoutes.py
    rm -f GetRoutes.py
    cat <<EOF > /root/acl/hy-v2rayn.json
{
    "server": "${IP}:${PORT}",
    "obfs": "${OBFS}",
    "up_mbps": 1000,
    "down_mbps": 1000,
    "insecure": true,
    "acl": "acl/routes.acl",
    "mmdb": "acl/Country.mmdb",
    "retry": 3,
    "retry_interval": 5,
    "socks5": {
        "listen": "127.0.0.1:10808",
        "timeout" : 300,
        "disable_udp": false
    },
    "http": {
        "listen": "127.0.0.1:10809",
        "timeout" : 300,
        "disable_udp": false
    }
}
EOF
    cat <<'TEXT' > /etc/systemd/system/hysteria.service
[Unit]
Description=Hysiteria Server Service
After=network.target

[Install]
WantedBy=multi-user.target

[Service]
Type=simple
WorkingDirectory=/etc/hysteria
ExecStart=/usr/local/bin/hysteria -c /etc/hysteria/config.json server
Restart=always
TEXT
    url="hysteria://${IP}:${PORT}?auth=${OBFS}&upmbps=1000&downmbps=1000&obfs=xplus&obfsParam=${OBFS}"
    echo ${url} > /root/hy-url.txt
}

installBBR() {
    result=$(lsmod | grep bbr)
    if [[ $result != "" ]]; then
        green "BBR模块已安装"
        return
    fi
    res=`systemd-detect-virt`
    if [[ $res =~ openvz|lxc ]]; then
        red "由于你的VPS为OpenVZ或LXC架构的VPS，跳过安装"
        return
    fi
    
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    result=$(lsmod | grep bbr)
    if [[ "$result" != "" ]]; then
        green "BBR模块已启用"
        return
    fi

    green "正在安装BBR模块..."
    if [[ $SYSTEM = "CentOS" ]]; then
        rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
        rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-4.el7.elrepo.noarch.rpm
        ${PACKAGE_INSTALL[int]} --enablerepo=elrepo-kernel kernel-ml
        ${PACKAGE_REMOVE[int]} kernel-3.*
        grub2-set-default 0
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    else
        ${PACKAGE_INSTALL[int]} --install-recommends linux-generic-hwe-16.04
        grub-set-default 0
        echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    fi
}

install_hysteria() {
    install_base
    wgcfv6status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2) 
    wgcfv4status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $wgcfv4status =~ "on"|"plus" ]] || [[ $wgcfv6status =~ "on"|"plus" ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        check_ip
        wg-quick up wgcf >/dev/null 2>&1
    else
        check_ip
    fi
    downloadHysteria
    read -rp "是否安装BBR [Y/N]: " YN
    if [[ $YN =~ "y"|"Y" ]]; then
        installBBR
    fi
    makeConfig
    systemctl enable hysteria
    systemctl start hysteria
    check_status
    if [[ -n $(service hysteria status 2>/dev/null | grep "inactive") ]]; then
        red "Hysteria 服务器安装失败"
    elif [[ -n $(service hysteria status 2>/dev/null | grep "active") ]]; then
        show_usage
        green "Hysteria 服务器安装成功"
        yellow "Hysteria 官方客户端配置文件已保存到 /root/hy-client.json"
        yellow "V2rayN 客户端规则配置文件已保存到 /root/acl 文件夹中"
        yellow "SagerNet / ShadowRocket 分享链接如下，并保存至 /root/hy-url.txt 文件中"
        green "$url"
    fi
}

start_hysteria() {
    systemctl start hysteria
    green "Hysteria 已启动！"
}

stop_hysteria() {
    systemctl stop hysteria
    green "Hysteria 已停止！"
}

restart_hysteria(){
    systemctl restart hysteria
    green "Hysteria 已重启！"
}

update_hysteria(){
    last_version=$(curl -Ls "https://api.github.com/repos/HyNetwork/Hysteria/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || last_version=v$(curl -Ls "https://data.jsdelivr.com/v1/package/resolve/gh/HyNetwork/Hysteria" | grep '"version":' | sed -E 's/.*"([^"]+)".*/\1/')
    local_version=$(/usr/local/bin/hysteria -v | awk 'NR==1 {print $3}')
    if [[ $last_version == $local_version ]]; then
        red "您当前运行的 Hysteria 内核为官方最新版本，不必再次更新！"
    else
        systemctl stop hysteria
        rm -f /usr/local/bin/hysteria
        wget -N --no-check-certificate https://github.com/HyNetwork/Hysteria/releases/download/${last_version}/Hysteria-tun-linux-$(archAffix) -O /usr/local/bin/hysteria
        chmod +x /usr/local/bin/hysteria
        systemctl start hysteria
        green "Hysteria 内核已更新到最新版本！"
    fi
}

view_log(){
    service hysteria status
}

uninstall_hysteria(){
    systemctl stop hysteria
    systemctl disable hysteria
    rm -rf /etc/hysteria
    rm -f /usr/local/bin/hysteria /usr/local/bin/hy
    rm -f /etc/systemd/system/hysteria.service
    green "Hysteria 已彻底卸载完成！"
}

check_status(){
    if [[ -n $(service hysteria status 2>/dev/null | grep "inactive") ]]; then
        status="${RED}未启动${PLAIN}"
    elif [[ -n $(service hysteria status 2>/dev/null | grep "active") ]]; then
        status="${GREEN}已启动${PLAIN}"
    else
        status="${RED}未安装${PLAIN}"
    fi
}

# 放开防火墙端口
open_ports() {
    systemctl stop firewalld.service 2>/dev/null
    systemctl disable firewalld.service 2>/dev/null
    setenforce 0 2>/dev/null
    ufw disable 2>/dev/null
    iptables -P INPUT ACCEPT 2>/dev/null
    iptables -P FORWARD ACCEPT 2>/dev/null
    iptables -P OUTPUT ACCEPT 2>/dev/null
    iptables -t nat -F 2>/dev/null
    iptables -t mangle -F 2>/dev/null
    iptables -F 2>/dev/null
    iptables -X 2>/dev/null
    netfilter-persistent save 2>/dev/null
    green "VPS网络防火墙端口已成功放行！"
}

#禁用IPv6
closeipv6() {
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.d/99-sysctl.conf
    sysctl --system
    green "禁用IPv6结束，可能需要重启VPS系统！"
}

#开启IPv6
openipv6() {
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0" >>/etc/sysctl.d/99-sysctl.conf
    sysctl --system
    green "开启IPv6结束，可能需要重启VPS系统！"
}

update_v2rule(){
    cd /root/acl
    rm -f Country.mmdb routes.acl
    wget -N https://raw.githubusercontent.com/taffychan/hysteria/main/GetRoutes.py
    python3 GetRoutes.py
    rm -f GetRoutes.py
    green "V2rayN 规则已更新完成！"
}

change_resolve(){
    currResolve=$(cat /etc/hysteria/config.json 2>/dev/null | grep resolve_preference | awk '{print $2}' | awk -F '"' '{ print $2}')
    yellow "请选择IP优先级："
    green "1. IPv4 优先"
    green "2. IPv6 优先"
    read -rp "请选择优先级 [1-2]:" newResolve
    case $newResolve in
        1) newResolve="46" && sed -i "4s/$currResolve/$newResolve/g" /etc/hysteria/config.json && systemctl restart hysteria && green "更改IPv4 优先成功！" ;;
        2) newResolve="64" && sed -i "4s/$currResolve/$newResolve/g" /etc/hysteria/config.json && systemctl restart hysteria && green "更改IPv6 优先成功！" ;;
        *) red "请选择正确的操作！" && exit 1 ;;
    esac
}

change_port(){
    currPort=$(cat /etc/hysteria/config.json 2>/dev/null | grep listen | awk '{print $2}' | awk -F '"' '{ print $2}')
    read -rp "请输入 Hysteria 的连接端口 [默认随机生成]: " newPort
    [[ -z $newPort ]] && newPort=$(shuf -i 1000-65535 -n 1)
    if [[ -n $(ss -ntlp | awk '{print $4}' | grep -w "$newPort") ]]; then
        until [[ -z $(ss -ntlp | awk '{print $4}' | grep -w "$newPort") ]]; do
            if [[ -n $(ss -ntlp | awk '{print $4}' | grep -w "$newPort") ]]; then
                yellow "你设置的端口目前已被其他程序占用，请重新设置一个新的端口"
                read -rp "请输入 Hysteria 的连接端口 [默认随机生成]: " newPort
                [[ -z $newPort ]] && newPort=$(shuf -i 1000-65535 -n 1)
            fi
        done
    fi
    nePort=":${newPort}"
    sed -i "s/$currPort/$nePort/g" /etc/hysteria/config.json
    sed -i "s/$currPort/$nePort/g" /root/hy-client.json
    sed -i "s/$currPort/$nePort/g" /root/acl/hy-v2rayn.json
    rm -f hy-url.txt
    check_ip
    OBFS=$(cat /etc/hysteria/config.json 2>/dev/null | grep obfs | awk '{print $2}' | awk -F '"' '{ print $2}')
    url="hysteria://${IP}:${newPort}?auth=${OBFS}&upmbps=1000&downmbps=1000&obfs=xplus&obfsParam=${OBFS}"
    echo ${url} > /root/hy-url.txt
    systemctl restart hysteria
    green "Hysteria 端口更改为：${newPort} 成功！"
    yellow "配置文件已更新，请重新在客户端导入节点链接或配置文件"
}

show_usage(){
    echo "Hysteria 脚本快捷指令使用方法: "
    echo "------------------------------------------"
    echo "hy              - 显示管理菜单 (功能更多)"
    echo "hy install      - 安装 Hysteria"
    echo "hy uninstall    - 卸载 Hysteria"
    echo "hy update       - 更新 Hysteria 内核"
    echo "hy on           - 启动 Hysteria"
    echo "hy off          - 关闭 Hysteria"
    echo "hy restart      - 重启 Hysteria"
    echo "hy log          - 查看 Hysteria 日志"
    echo "------------------------------------------"
}

menu() {
    clear
    check_status
    echo "#############################################################"
    echo -e "#                   ${RED}Hysteria  一键安装脚本${PLAIN}                  #"
    echo -e "# ${GREEN}作者${PLAIN}: taffychan                                           #"
    echo -e "# ${GREEN}GitHub${PLAIN}: https://github.com/taffychan                      #"
    echo "#############################################################"
    echo ""
    yellow "注意：部分VPS服务器提供商有可能限制Hysteria协议的部署和使用，请谨慎部署"
    echo ""
    echo -e "  ${GREEN}1.${PLAIN}  安装 Hysieria"
    echo -e "  ${GREEN}2.${PLAIN}  ${RED}卸载 Hysieria${PLAIN}"
    echo " -------------"
    echo -e "  ${GREEN}3.${PLAIN}  启动 Hysieria"
    echo -e "  ${GREEN}4.${PLAIN}  重启 Hysieria"
    echo -e "  ${GREEN}5.${PLAIN}  停止 Hysieria"
    echo -e "  ${GREEN}6.${PLAIN}  更新 Hysieria 内核"
    echo " -------------"
    echo -e "  ${GREEN}7.${PLAIN}  修改 Hysteria IP优先级"
    echo -e "  ${GREEN}8.${PLAIN}  修改 Hysteria 连接端口"
    echo -e "  ${GREEN}9.${PLAIN}  更新 V2rayN 入站规则"
    echo " -------------"
    echo -e "  ${GREEN}10.${PLAIN}  查看 Hysieria 运行日志"
    echo " -------------"
    echo -e "  ${GREEN}11.${PLAIN}  启用IPv6"
    echo -e "  ${GREEN}12.${PLAIN}  禁用IPv6"
    echo -e "  ${GREEN}13.${PLAIN}  放行防火墙端口"
    echo " -------------"
    echo -e "  ${GREEN}0.${PLAIN} 退出"
    echo ""
    echo -e "Hysteria 状态：$status"
    echo ""
    read -rp " 请选择操作 [0-12] ：" answer
    case $answer in
        1) install_hysteria ;;
        2) uninstall_hysteria ;;
        3) start_hysteria ;;
        4) restart_hysteria ;;
        5) stop_hysteria ;;
        6) update_hysteria ;;
        7) change_resolve ;;
        8) change_port ;;
        9) update_v2rule ;;
        10) view_log ;;
        11) openipv6 ;;
        12) closeipv6 ;;
        13) open_ports ;;
        *) red "请选择正确的操作！" && exit 1 ;;
    esac
}

if [[ ! -f /usr/local/bin/hy ]]; then
    cp hysteria.sh /usr/local/bin/hy
    chmod +x /usr/local/bin/hy
fi

if [[ $# > 0 ]]; then
    case $1 in
        install ) install_hysteria ;;
        uninstall ) uninstall_hysteria ;;
        update ) update_hysteria ;;
        on ) start_hysteria ;;
        off ) stop_hysteria ;;
        restart ) restart_hysteria ;;
        log ) view_log ;;
        * ) show_usage ;;
    esac
else
    menu
fi
