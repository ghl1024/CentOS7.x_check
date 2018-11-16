#!/bin/bash


export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin
source /etc/profile

[ $(id -u) -gt 0 ] && echo "请用root用户执行此脚本！" && exit 1
#uploadHostDailyCheckApi="http://10.0.0.1:8080/api/uploadHostDailyCheck"
#uploadHostDailyCheckReportApi="http://10.0.0.1:8080/api/uploadHostDailyCheckReport"
centosVersion=$(awk '{print $(NF-1)}' /etc/redhat-release)
VERSION=`date +%F`

#日志相关
PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
[ -f $PROGPATH ] && PROGPATH="."
LOGPATH="$PROGPATH/log"
[ -e $LOGPATH ] || mkdir $LOGPATH
RESULTFILE="$LOGPATH/HostDailyCheck-`hostname`-`date +%Y%m%d`.txt"


#定义报表的全局变量
report_DateTime=""  
report_Hostname=""   
report_OSRelease=""    
report_Kernel=""   
report_Language=""   
report_LastReboot=""   
report_Uptime=""   
report_CPUs=""  
report_CPUType=""  
report_Arch=""   
report_MemTotal=""    
report_MemFree=""   
report_MemUsedPercent=""   
report_DiskTotal=""    
report_DiskFree=""    
report_DiskUsedPercent=""    
report_InodeTotal=""   
report_InodeFree="" 
report_InodeUsedPercent=""  
report_IP=""  
report_MAC=""   
report_Gateway=""   
report_DNS=""   
report_Listen=""   
report_Selinux=""  
report_Firewall=""   
report_USERs=""   
report_USEREmptyPassword=""  
report_USERTheSameUID=""      
report_PasswordExpiry=""    
report_RootUser=""   
report_Sudoers=""   
report_SSHAuthorized=""   
report_SSHDProtocolVersion=""    
report_SSHDPermitRootLogin=""   
report_DefunctProsess=""    
report_SelfInitiatedService=""   
report_SelfInitiatedProgram=""   
report_RuningService=""           
report_Crontab=""    
report_Syslog=""   
report_SNMP=""    
report_NTP=""    
report_JDK=""   
function version(){
    echo ""
    echo ""
    echo "系统巡检脚本：Version $VERSION"
}

function getCpuStatus(){
    echo ""
    echo -e "\033[33m*******************************************************CPU检查*******************************************************\033[0m"
    Physical_CPUs=$(grep "physical id" /proc/cpuinfo| sort | uniq | wc -l)
    Virt_CPUs=$(grep "processor" /proc/cpuinfo | wc -l)
    CPU_Kernels=$(grep "cores" /proc/cpuinfo|uniq| awk -F ': ' '{print $2}')
    CPU_Type=$(grep "model name" /proc/cpuinfo | awk -F ': ' '{print $2}' | sort | uniq)
    CPU_Arch=$(uname -m)
    echo "物理CPU个数:$Physical_CPUs"
    echo "逻辑CPU个数:$Virt_CPUs"
    echo "每CPU核心数:$CPU_Kernels"
    echo "    CPU型号:$CPU_Type"
    echo "    CPU架构:$CPU_Arch"
    #报表信息
    report_CPUs=$Virt_CPUs 
    report_CPUType=$CPU_Type 
    report_Arch=$CPU_Arch   
}

function getMemStatus(){
    echo ""
    echo  -e "\033[33m*******************************************************内存检查*******************************************************\033[0m"
    if [[ $centosVersion < 7 ]];then
        free -mo
    else
        free -h
    fi
    #报表信息
    MemTotal=$(grep MemTotal /proc/meminfo| awk '{print $2}')  #KB
    MemFree=$(grep MemFree /proc/meminfo| awk '{print $2}')    #KB
    let MemUsed=MemTotal-MemFree
    MemPercent=$(awk "BEGIN {if($MemTotal==0){printf 100}else{printf \"%.2f\",$MemUsed*100/$MemTotal}}")
    report_MemTotal="$((MemTotal/1024))""MB"      
    report_MemFree="$((MemFree/1024))""MB"       
    report_MemUsedPercent="$(awk "BEGIN {if($MemTotal==0){printf 100}else{printf \"%.2f\",$MemUsed*100/$MemTotal}}")""%"  
}

function getDiskStatus(){
    echo ""
    echo -e "\033[33m*******************************************************磁盘检查*******************************************************\033[0m"
    df -hiP | sed 's/Mounted on/Mounted/'> /tmp/inode
    df -hTP | sed 's/Mounted on/Mounted/'> /tmp/disk 
    join /tmp/disk /tmp/inode | awk '{print $1,$2,"|",$3,$4,$5,$6,"|",$8,$9,$10,$11,"|",$12}'| column -t
    #报表信息
    diskdata=$(df -TP | sed '1d' | awk '$2!="tmpfs"{print}') #KB
    disktotal=$(echo "$diskdata" | awk '{total+=$3}END{print total}') #KB
    diskused=$(echo "$diskdata" | awk '{total+=$4}END{print total}')  #KB
    diskfree=$((disktotal-diskused)) #KB
    diskusedpercent=$(echo $disktotal $diskused | awk '{if($1==0){printf 100}else{printf "%.2f",$2*100/$1}}') 
    inodedata=$(df -iTP | sed '1d' | awk '$2!="tmpfs"{print}')
    inodetotal=$(echo "$inodedata" | awk '{total+=$3}END{print total}')
    inodeused=$(echo "$inodedata" | awk '{total+=$4}END{print total}')
    inodefree=$((inodetotal-inodeused))
    inodeusedpercent=$(echo $inodetotal $inodeused | awk '{if($1==0){printf 100}else{printf "%.2f",$2*100/$1}}')
    report_DiskTotal=$((disktotal/1024/1024))"GB" 
    report_DiskFree=$((diskfree/1024/1024))"GB"   
    report_DiskUsedPercent="$diskusedpercent""%"   
    report_InodeTotal=$((inodetotal/1000))"K"     
    report_InodeFree=$((inodefree/1000))"K"       
    report_InodeUsedPercent="$inodeusedpercent""%" 

}

function getSystemStatus(){
    echo ""
    echo -e "\033[33m*******************************************************系统检查 *******************************************************\033[0m"
    if [ -e /etc/sysconfig/i18n ];then
        default_LANG="$(grep "LANG=" /etc/sysconfig/i18n | grep -v "^#" | awk -F '"' '{print $2}')"
    else
        default_LANG=$LANG
    fi
    export LANG="en_US.UTF-8"
    Release=$(cat /etc/redhat-release 2>/dev/null)
    Kernel=$(uname -r)
    OS=$(uname -o)
    Hostname=$(uname -n)
    SELinux=$(/usr/sbin/sestatus | grep "SELinux status: " | awk '{print $3}')
    LastReboot=$(who -b | awk '{print $3,$4}')
    uptime=$(uptime | sed 's/.*up \([^,]*\), .*/\1/')
    echo "     系统：$OS"
    echo " 发行版本：$Release"
    echo "     内核：$Kernel"
    echo "   主机名：$Hostname"
    echo "  SELinux：$SELinux"
    echo "语言/编码：$default_LANG"
    echo " 当前时间：$(date +'%F %T')"
    echo " 最后启动：$LastReboot"
    echo " 运行时间：$uptime"
    #报表信息
    report_DateTime=$(date +"%F %T")  
    report_Hostname="$Hostname"     
    report_OSRelease="$Release"       
    report_Kernel="$Kernel"           
    report_Language="$default_LANG"   
    report_LastReboot="$LastReboot"   
    report_Uptime="$uptime"          
    report_Selinux="$SELinux"
    export LANG="$default_LANG"

}

function getServiceStatus(){
    echo ""
    echo -e "\033[33m*******************************************************服务检查*******************************************************\033[0m"
    echo ""
    if [[ $centosVersion > 7 ]];then
        conf=$(systemctl list-unit-files --type=service --state=enabled --no-pager | grep "enabled")
        process=$(systemctl list-units --type=service --state=running --no-pager | grep ".service")
        #报表信息
        report_SelfInitiatedService="$(echo "$conf" | wc -l)"     
        report_RuningService="$(echo "$process" | wc -l)"         
    else
        conf=$(/sbin/chkconfig | grep -E ":on|:启用")
        process=$(/sbin/service --status-all 2>/dev/null | grep -E "is running|正在运行")
        #报表信息
        report_SelfInitiatedService="$(echo "$conf" | wc -l)"      
        report_RuningService="$(echo "$process" | wc -l)"          
    fi
    echo "服务配置"
    echo "--------"
    echo "$conf"  | column -t
    echo ""
    echo "正在运行的服务"
    echo "--------------"
    echo "$process"

}


function getAutoStartStatus(){
    echo ""
    echo -e "\033[33m*******************************************************自启动检查*******************************************************\033[0m"
    conf=$(grep -v "^#" /etc/rc.d/rc.local| sed '/^$/d')
    echo "$conf"
    #报表信息
    report_SelfInitiatedProgram="$(echo $conf | wc -l)"   
}

function getLoginStatus(){
    echo ""
    echo -e "\033[33m*******************************************************登录检查*******************************************************\033[0m"
    last | head
}

function getNetworkStatus(){
    echo ""
    echo -e "\033[33m*******************************************************网络检查*******************************************************\033[0m"
    if [[ $centosVersion < 7 ]];then
        /sbin/ifconfig -a | grep -v packets | grep -v collisions | grep -v inet6
    else
        #ip a
        for i in $(ip link | grep BROADCAST | awk -F: '{print $2}');do ip add show $i | grep -E "BROADCAST|global"| awk '{print $2}' | tr '\n' ' ' ;echo "" ;done
    fi
    GATEWAY=$(ip route | grep default | awk '{print $3}')
    DNS=$(grep nameserver /etc/resolv.conf| grep -v "#" | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')
    echo ""
    echo "网关：$GATEWAY "
    echo "DNS：$DNS"
    #报表信息
    IP=$(ip -f inet addr | grep -v 127.0.0.1 |  grep inet | awk '{print $NF,$2}' | tr '\n' ',' | sed 's/,$//')
    MAC=$(ip link | grep -v "LOOPBACK\|loopback" | awk '{print $2}' | sed 'N;s/\n//' | tr '\n' ',' | sed 's/,$//')
    report_IP="$IP"         
    report_MAC=$MAC          
    report_Gateway="$GATEWAY" 
    report_DNS="$DNS"
    echo ""
ping -c 4 www.baidu.com >/dev/null 2>&1
if [ $? -eq 0 ];then
   echo "网络连接：正常" 
else
   echo "网络连接：异常"
fi 
}

function getListenStatus(){
    echo ""
    echo  -e "\033[33m*******************************************************监听检查*******************************************************\033[0m"
    TCPListen=$(ss -ntul | column -t)
    echo "$TCPListen"
    #报表信息
    report_Listen="$(echo "$TCPListen"| sed '1d' | awk '/tcp/ {print $5}' | awk -F: '{print $NF}' | sort | uniq | wc -l)"
}

function getCronStatus(){
    echo ""
    echo -e "\033[33m*******************************************************计划任务检查*******************************************************\033[0m"
    Crontab=0
    for shell in $(grep -v "/sbin/nologin" /etc/shells);do
        for user in $(grep "$shell" /etc/passwd| awk -F: '{print $1}');do
            crontab -l -u $user >/dev/null 2>&1
            status=$?
            if [ $status -eq 0 ];then
                echo "$user"
                echo "--------"
                crontab -l -u $user
                let Crontab=Crontab+$(crontab -l -u $user | wc -l)
                echo ""
            fi
        done
    done
    #计划任务
    find /etc/cron* -type f | xargs -i ls -l {} | column  -t
    let Crontab=Crontab+$(find /etc/cron* -type f | wc -l)
    #报表信息
    report_Crontab="$Crontab"   
}
function getHowLongAgo(){
    # 计算一个时间戳离现在有多久了
    datetime="$*"
    [ -z "$datetime" ] && echo `stat /etc/passwd|awk "NR==6"`
    Timestamp=$(date +%s -d "$datetime")  
    Now_Timestamp=$(date +%s)
    Difference_Timestamp=$(($Now_Timestamp-$Timestamp))
    days=0;hours=0;minutes=0;
    sec_in_day=$((60*60*24));
    sec_in_hour=$((60*60));
    sec_in_minute=60
    while (( $(($Difference_Timestamp-$sec_in_day)) > 1 ))
    do
        let Difference_Timestamp=Difference_Timestamp-sec_in_day
        let days++
    done
    while (( $(($Difference_Timestamp-$sec_in_hour)) > 1 ))
    do
        let Difference_Timestamp=Difference_Timestamp-sec_in_hour
        let hours++
    done
    echo "$days 天 $hours 小时前"
}

function getUserLastLogin(){
    # 获取用户最近一次登录的时间，含年份
    # 很遗憾last命令不支持显示年份，只有"last -t YYYYMMDDHHMMSS"表示某个时间之间的登录，我
    # 们只能用最笨的方法了，对比今天之前和今年元旦之前（或者去年之前和前年之前……）某个用户
    # 登录次数，如果登录统计次数有变化，则说明最近一次登录是今年。
    username=$1
    : ${username:="`whoami`"}
    thisYear=$(date +%Y)
    oldesYear=$(last | tail -n1 | awk '{print $NF}')
    while(( $thisYear >= $oldesYear));do
        loginBeforeToday=$(last $username | grep $username | wc -l)
        loginBeforeNewYearsDayOfThisYear=$(last $username -t $thisYear"0101000000" | grep $username | wc -l)
        if [ $loginBeforeToday -eq 0 ];then
            echo "从未登录过"
            break
        elif [ $loginBeforeToday -gt $loginBeforeNewYearsDayOfThisYear ];then
            lastDateTime=$(last -i $username | head -n1 | awk '{for(i=4;i<(NF-2);i++)printf"%s ",$i}')" $thisYear" 
            lastDateTime=$(date "+%Y-%m-%d %H:%M:%S" -d "$lastDateTime")
            echo "$lastDateTime"
            break
        else
            thisYear=$((thisYear-1))
        fi
    done

}

function getUserStatus(){
    echo ""
    echo -e "\033[33m*******************************************************用户检查*******************************************************\033[0m"
    #/etc/passwd 最后修改时间
    pwdfile="$(cat /etc/passwd)"
    Modify=$(stat /etc/passwd | grep Modify | tr '.' ' ' | awk '{print $2,$3}')

    echo "/etc/passwd: $Modify ($(getHowLongAgo $Modify))"
    echo ""
    echo "特权用户"
    echo "--------"
    RootUser=""
    for user in $(echo "$pwdfile" | awk -F: '{print $1}');do
        if [ $(id -u $user) -eq 0 ];then
            echo "$user"
            RootUser="$RootUser,$user"
        fi
    done
    echo ""
    echo "用户列表"
    echo "--------"
    USERs=0
    echo "$(
    echo "用户名 UID GID HOME SHELL 最后一次登录"
    for shell in $(grep -v "/sbin/nologin" /etc/shells);do
        for username in $(grep "$shell" /etc/passwd| awk -F: '{print $1}');do
            userLastLogin="$(getUserLastLogin $username)"
            echo "$pwdfile" | grep -w "$username" |grep -w "$shell"| awk -F: -v lastlogin="$(echo "$userLastLogin" | tr ' ' '_')" '{print $1,$3,$4,$6,$7,lastlogin}'
        done
        let USERs=USERs+$(echo "$pwdfile" | grep "$shell"| wc -l)
    done
    )" | column -t
    echo ""
    echo "空密码用户"
    echo "----------"
    USEREmptyPassword=""
    for shell in $(grep -v "/sbin/nologin" /etc/shells);do
            for user in $(echo "$pwdfile" | grep "$shell" | cut -d: -f1);do
            r=$(awk -F: '$2=="!!"{print $1}' /etc/shadow | grep -w $user)
            if [ ! -z $r ];then
                echo $r
                USEREmptyPassword="$USEREmptyPassword,"$r
            fi
        done    
    done
    echo ""
    echo "相同ID的用户"
    echo "------------"
    USERTheSameUID=""
    UIDs=$(cut -d: -f3 /etc/passwd | sort | uniq -c | awk '$1>1{print $2}')
    for uid in $UIDs;do
        echo -n "$uid";
        USERTheSameUID="$uid"
        r=$(awk -F: 'ORS="";$3=='"$uid"'{print ":",$1}' /etc/passwd)
        echo "$r"
        echo ""
        USERTheSameUID="$USERTheSameUID $r,"
    done
    #报表信息
    report_USERs="$USERs"  
    report_USEREmptyPassword=$(echo $USEREmptyPassword | sed 's/^,//') 
    report_USERTheSameUID=$(echo $USERTheSameUID | sed 's/,$//') 
    report_RootUser=$(echo $RootUser | sed 's/^,//')   
}


function getPasswordStatus {
    echo ""
    echo -e "\033[33m*******************************************************密码检查*******************************************************\033[0m"
    pwdfile="$(cat /etc/passwd)"
    echo ""
    echo "密码过期检查"
    echo "------------"
    result=""
    for shell in $(grep -v "/sbin/nologin" /etc/shells);do
        for user in $(echo "$pwdfile" | grep "$shell" | cut -d: -f1);do
            get_expiry_date=$(/usr/bin/chage -l $user | grep 'Password expires' | cut -d: -f2)
            if [[ $get_expiry_date = ' never' || $get_expiry_date = 'never' ]];then
                printf "%-15s 永不过期\n" $user
                result="$result,$user:never"
            else
                password_expiry_date=$(date -d "$get_expiry_date" "+%s")
                current_date=$(date "+%s")
                diff=$(($password_expiry_date-$current_date))
                let DAYS=$(($diff/(60*60*24)))
                printf "%-15s %s天后过期\n" $user $DAYS
                result="$result,$user:$DAYS days"
            fi
        done
    done
    report_PasswordExpiry=$(echo $result | sed 's/^,//')

    echo ""
    echo "密码策略检查"
    echo "------------"
    grep -v "#" /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE"


}

function getSudoersStatus(){
    echo ""
    echo -e "\033[33m*******************************************************Sudoers检查*******************************************************\033[0m"
    conf=$(grep -v "^#" /etc/sudoers| grep -v "^Defaults" | sed '/^$/d')
    echo "$conf"
    echo ""
    #报表信息
    report_Sudoers="$(echo $conf | wc -l)"
}

function getInstalledStatus(){
    echo ""
    echo -e "\033[33m*******************************************************软件检查*******************************************************\033[0m"
    rpm -qa --last | head | column -t 
}

function getProcessStatus(){
    echo ""
    echo -e "\033[33m*******************************************************进程检查*******************************************************\033[0m"
    if [ $(ps -ef | grep defunct | grep -v grep | wc -l) -ge 1 ];then
        echo ""
        echo "僵尸进程";
        echo "--------"
        ps -ef | head -n1
        ps -ef | grep defunct | grep -v grep
    fi
    echo ""
    echo "内存占用TOP10"
    echo "-------------"
    echo -e "PID %MEM RSS COMMAND
    $(ps aux | awk '{print $2, $4, $6, $11}' | sort -k3rn | head -n 10 )"| column -t 
    echo ""
    echo "CPU占用TOP10"
    echo "------------"
    top b -n1 | head -17 | tail -11
    #报表信息
    report_DefunctProsess="$(ps -ef | grep defunct | grep -v grep|wc -l)"
}

function getJDKStatus(){
    echo ""
    echo -e "\033[33m*******************************************************JDK检查*******************************************************\033[0m"
    java -version 2>/dev/null
    if [ $? -eq 0 ];then
        java -version 2>&1
    fi
    echo "JAVA_HOME=\"$JAVA_HOME\""
    #报表信息
    report_JDK="$(java -version 2>&1 | grep version | awk '{print $1,$3}' | tr -d '"')"
}
function getSyslogStatus(){
    echo ""
    echo -e "\033[33m*******************************************************syslog检查*******************************************************\033[0m"
    echo "服务状态：$(getState rsyslog)"
    echo ""
    echo "/etc/rsyslog.conf"
    echo "-----------------"
    cat /etc/rsyslog.conf 2>/dev/null | grep -v "^#" | grep -v "^\\$" | sed '/^$/d'  | column -t
    #报表信息
    report_Syslog="$(getState rsyslog)"
}
function getFirewallStatus(){
    echo ""
    echo -e "\033[33m******************************************************* 防火墙检查*******************************************************\033[0m"
    #防火墙状态，策略等
    if [[ $centosVersion = 7 ]];then
        systemctl status firewalld >/dev/null  2>&1
        status=$?
        if [ $status -eq 0 ];then
                s="active"
        elif [ $status -eq 3 ];then
                s="inactive"
        elif [ $status -eq 4 ];then
                s="permission denied"
        else
                s="unknown"
        fi
    else
        s="$(getState iptables)"
    fi
    echo "firewalld: $s"
    echo ""
    echo "/etc/sysconfig/firewalld"
    echo "-----------------------"
    cat /etc/sysconfig/firewalld 2>/dev/null
    #报表信息
    report_Firewall="$s"
}

function getSNMPStatus(){
    #SNMP服务状态，配置等
    echo ""
    echo -e "\033[33m*******************************************************SNMP检查*******************************************************\033[0m"
    status="$(getState snmpd)"
    echo "服务状态：$status"
    echo ""
    if [ -e /etc/snmp/snmpd.conf ];then
        echo "/etc/snmp/snmpd.conf"
        echo "--------------------"
        cat /etc/snmp/snmpd.conf 2>/dev/null | grep -v "^#" | sed '/^$/d'
    fi
    #报表信息
    report_SNMP="$(getState snmpd)"
}



function getState(){
    if [[ $centosVersion < 7 ]];then
        if [ -e "/etc/init.d/$1" ];then
            if [ `/etc/init.d/$1 status 2>/dev/null | grep -E "is running|正在运行" | wc -l` -ge 1 ];then
                r="active"
            else
                r="inactive"
            fi
        else
            r="unknown"
        fi
    else
        #CentOS 7+
        r="$(systemctl is-active $1 2>&1)"
    fi
    echo "$r"
}

function getSSHStatus(){
    #SSHD服务状态，配置,受信任主机等
    echo ""
    echo -e "\033[33m*******************************************************SSH检查*******************************************************\033[0m"
    #检查受信任主机
    pwdfile="$(cat /etc/passwd)"
    echo "服务状态：$(getState sshd)"
    Protocol_Version=$(cat /etc/ssh/sshd_config | grep Protocol | awk '{print $2}')
    echo "SSH协议版本：$Protocol_Version"
    echo ""
    echo "信任主机"
    echo "--------"
    authorized=0
    for user in $(echo "$pwdfile" | grep /bin/bash | awk -F: '{print $1}');do
        authorize_file=$(echo "$pwdfile" | grep -w $user | awk -F: '{printf $6"/.ssh/authorized_keys"}')
        authorized_host=$(cat $authorize_file 2>/dev/null | awk '{print $3}' | tr '\n' ',' | sed 's/,$//')
        if [ ! -z $authorized_host ];then
            echo "$user 授权 \"$authorized_host\" 无密码访问"
        fi
        let authorized=authorized+$(cat $authorize_file 2>/dev/null | awk '{print $3}'|wc -l)
    done

    echo ""
    echo "是否允许ROOT远程登录"
    echo "--------------------"
    config=$(cat /etc/ssh/sshd_config | grep PermitRootLogin)
    firstChar=${config:0:1}
    if [ $firstChar == "#" ];then
        PermitRootLogin="yes" 
    else
        PermitRootLogin=$(echo $config | awk '{print $2}')
    fi
    echo "PermitRootLogin $PermitRootLogin"

    echo ""
    echo "/etc/ssh/sshd_config"
    echo "--------------------"
    cat /etc/ssh/sshd_config | grep -v "^#" | sed '/^$/d'

    #报表信息
    report_SSHAuthorized="$authorized"   
    report_SSHDProtocolVersion="$Protocol_Version"   
    report_SSHDPermitRootLogin="$PermitRootLogin"    
}
function getNTPStatus(){
    #NTP服务状态，当前时间，配置等
    echo ""
    echo -e "\033[33m*******************************************************NTP检查*******************************************************\033[0m"
    if [ -e /etc/ntp.conf ];then
        echo "服务状态：$(getState ntpd)"
        echo ""
        echo "/etc/ntp.conf"
        echo "-------------"
        cat /etc/ntp.conf 2>/dev/null | grep -v "^#" | sed '/^$/d'
    fi
    #报表信息
    report_NTP="$(getState ntpd)"
}


function uploadHostDailyCheckReport(){
    json="{
        \"DateTime\":\"$report_DateTime\",
        \"Hostname\":\"$report_Hostname\",
        \"OSRelease\":\"$report_OSRelease\",
        \"Kernel\":\"$report_Kernel\",
        \"Language\":\"$report_Language\",
        \"LastReboot\":\"$report_LastReboot\",
        \"Uptime\":\"$report_Uptime\",
        \"CPUs\":\"$report_CPUs\",
        \"CPUType\":\"$report_CPUType\",
        \"Arch\":\"$report_Arch\",
        \"MemTotal\":\"$report_MemTotal\",
        \"MemFree\":\"$report_MemFree\",
        \"MemUsedPercent\":\"$report_MemUsedPercent\",
        \"DiskTotal\":\"$report_DiskTotal\",
        \"DiskFree\":\"$report_DiskFree\",
        \"DiskUsedPercent\":\"$report_DiskUsedPercent\",
        \"InodeTotal\":\"$report_InodeTotal\",
        \"InodeFree\":\"$report_InodeFree\",
        \"InodeUsedPercent\":\"$report_InodeUsedPercent\",
        \"IP\":\"$report_IP\",
        \"MAC\":\"$report_MAC\",
        \"Gateway\":\"$report_Gateway\",
        \"DNS\":\"$report_DNS\",
        \"Listen\":\"$report_Listen\",
        \"Selinux\":\"$report_Selinux\",
        \"Firewall\":\"$report_Firewall\",
        \"USERs\":\"$report_USERs\",
        \"USEREmptyPassword\":\"$report_USEREmptyPassword\",
        \"USERTheSameUID\":\"$report_USERTheSameUID\",
        \"PasswordExpiry\":\"$report_PasswordExpiry\",
        \"RootUser\":\"$report_RootUser\",
        \"Sudoers\":\"$report_Sudoers\",
        \"SSHAuthorized\":\"$report_SSHAuthorized\",
        \"SSHDProtocolVersion\":\"$report_SSHDProtocolVersion\",
        \"SSHDPermitRootLogin\":\"$report_SSHDPermitRootLogin\",
        \"DefunctProsess\":\"$report_DefunctProsess\",
        \"SelfInitiatedService\":\"$report_SelfInitiatedService\",
        \"SelfInitiatedProgram\":\"$report_SelfInitiatedProgram\",
        \"RuningService\":\"$report_RuningService\",
        \"Crontab\":\"$report_Crontab\",
        \"Syslog\":\"$report_Syslog\",
        \"SNMP\":\"$report_SNMP\",
        \"NTP\":\"$report_NTP\",
        \"JDK\":\"$report_JDK\"
    }"
    #echo "$json" 
    curl -l -H "Content-type: application/json" -X POST -d "$json" "$uploadHostDailyCheckReportApi" 2>/dev/null
}

function check(){
    version
    getSystemStatus
    getCpuStatus
    getMemStatus
    getDiskStatus
    getNetworkStatus
    getListenStatus
    getProcessStatus
    getServiceStatus
    getAutoStartStatus
    getLoginStatus
    getCronStatus
    getUserStatus
    getPasswordStatus
    getSudoersStatus
    getJDKStatus
    getFirewallStatus
    getSSHStatus
    getSyslogStatus
    getSNMPStatus
    getNTPStatus
    getInstalledStatus
}

#执行检查并保存检查结果
check > $RESULTFILE

echo -e "\033[44;37m 检查结果存放在：$RESULTFILE \033[0m"

#上传检查结果的文件
#curl -F "filename=@$RESULTFILE" "$uploadHostDailyCheckApi" 2>/dev/null