#!/bin/bash
#######################################
# Red Onion Install Script v0.2
# https://github.com/hadojae/redonion
# tested on Centos/RHEL 7.1
########################################

####################################################
### MODIFY THESE GLOBALS TO SUIT YOUR DEPLOYMENT ###
####################################################

sniff_int="eno33554984"            			# Whatever interface you will use for sniffing  
manage_int="eno16777736"           			# Whatever interface you will use for management  
manage_ip="10.10.2.119"      			    # Management IP address                     
user_drop="ro"          			        # A user account to drop permissions to during install
wrk_dir="/home/ro/redonion"                 # The directory you will be installing from
num_bro_pf_proc="4"           			    # The number of BRO load balanced worked processes you want to run 
install_dir="/opt"          			    # Where you want to install the tools
pf_num_rings="32768"        			    # Number of rings you want to allocate for pf_ring      
pf_trans_mode="0"           			    # Mode you want pf_ring to run in - 0 (no pfring nic drivers) 1 (both) or 2 (only pfring drivers)
etpro_license=""                            # Enter in etpro license, if empty will install community ruleset
proxy_ip=""                                 # Proxy IP address/dns
proxy_port=""                               # Proxy Port

### Moloch Config Variables ###
es_mem="1G"					                    # How much memory should elasticsearch for moloch have? (< 32G)
moloch_user="ro"				                # What user should moloch use
moloch_group="ro"				                # What group should moloch use
moloch_password="OmG_R0_Rul3z!1!"       # Password for Moloch
moloch_fqdn="redonion.localhost"        # FQDN for Moloch Cert
moloch_country="US"				              # Country for Moloch Cert
moloch_state="IL" 				              # State for Moloch Cert
moloch_orgname="BLAH"             		  # Org Name for Moloch Cert
moloch_orgunit="NO"				              # Org unit for Moloch Cert
moloch_locality="HERE"				          # Locality for Moloch Cert
es_ver="1.5.2"					                # What version of elasticsearch are you using for moloch?
esdb_dir="$install_dir/esdb"            # Where should Moloch store elasticsearch data?
pcap_data_dir="$install_dir/moloch/raw" # Where should Moloch store raw pcaps? eg. $dir_1;$dir_2;$dir_3

#netflow_collector="10.10.2.120:9995"		# IP address and port of a netflow collector. If none leave empty.
#netflow_version="5"				            # What version of Netflow do you want to use? If none leave empty.

### Log Aggregation Globals ###
log_method="logstash_elasticsearch"		  # options are splunk, logstash_elasticsearch, or logstash_syslog

splunk_fwd="10.10.2.23:9997"				    # if using splunk, the ip and port you're forwarding logs to, if multiple separate by comma and space
splunk_bro_index="redonion_bro"			    # if using splunk, the name of the index you want to use for Bro logs
splunk_suricata_index="redonion_suri"		# if using splunk, the name of the index you want to use for Suricata logs

logstash_elasticsearch_host="10.10.2.23"	# if using logstash_elasticsearch mode - the host/ip of your receiving node on your cluster
logstash_elasticsearch_port=9200		      # if using logstash_elasticsearch mode - the port elasticsearch wants traffic on *no quotes

logstash_syslog_ip="10.10.2.23"           # if using logstash_syslog, the ip of your syslog receiver
logstash_syslog_port=514			            # if using logstash_syslog, the port your syslog receiver expects traffic on *no quotes
logstash_syslog_protocol="udp"			      # if using logstash_syslog, the protocol you want to use - tcp or udp 

#############################################
##### LEAVE EVERYTHING BELOW THIS ALONE #####
#############################################

# Pretty status notifications / error handling function
function print_status ()
{
    echo -e "\x1B[01;34m[*]\x1B[0m $1"
}

function print_good ()
{
    echo -e "\x1B[01;32m[*]\x1B[0m $1"
}

function print_error ()
{
    echo -e "\x1B[01;31m[*]\x1B[0m $1"
}

function print_notification ()
{
  echo -e "\x1B[01;33m[*]\x1B[0m $1"
}

function handle_error ()
{
    if  [ $? == 0 ]; then
      print_good "Success!"
    else
      print_error "Failure...exiting..."
      exit $?
    fi
}

function pause() 
{
   read -p "$*"
}

function space_pls()
{
   echo -e "\n";
}

function logo()
{
space_pls
echo -e "\x1B[01;31m.______  ._______.______       ._______  .______  .___ ._______  .______  \x1B[0m"
echo -e "\x1B[01;31m: __   \ : .____/:_ _   \      : .___  \ :      \ : __|: .___  \ :      \ \x1B[0m"
echo -e "\x1B[01;31m|  \____|| : _/\ |   |   |     | :   |  ||       || : || :   |  ||       |\x1B[0m"
echo -e "\x1B[01;31m|   :  \ |   /  \| . |   |     |     :  ||   |   ||   ||     :  ||   |   |\x1B[0m"
echo -e "\x1B[01;31m|   |___\|_.: __/|. ____/       \_. ___/ |___|   ||   | \_. ___/ |___|   |\x1B[0m"
echo -e "\x1B[01;31m|___|       :/    :/              :/         |___||___|   :/         |___|\x1B[0m"
echo -e "\x1B[01;31m                  :               :                       :               \x1B[0m"
echo -e ""
echo -e "\x1B[01;30m        CENTOS/RHEL+PFRING+SURICATA+BRO+MOLOCH+ET+SPLUNK/ELK==WIN!        \x1B[0m"
echo -e ""
echo -e "\x1B[01;32m           REDONION v0.2 {https://github.com/hadojae/redonion}            \x1B[0m"
space_pls
}

########################################
# Functions...

function letsgo () 
{

source /etc/profile

  #Check for root user
  if [ "$UID" -eq 0 ]; then
    sleep 0
  else
    print_error "Check for root user failed. Please run this script as root."
    exit 1
  fi

  # Check for work directory
    if [ ! -d $wrk_dir ]; then
      print_error "Your defined work directory does not seem to exist. Check if wrk_dir is set to the directory where you cloned redonion."
      exit 0
    fi

  # Check to see that we're on Centos 7
  if [ -f /etc/centos-release ]; then
    distro="CentOS"
    if [[ ! `grep "release 7" /etc/centos-release` ]]; then
      print_error "This build script is for CENTOS 7. Please update via yum or use the proper version."
      exit 0
    fi
  fi

  # Haven't tested on RHEL7 yet
  if [ -f /etc/redhat-release ]; then
    distro="RHEL"
    if [[ ! `grep "release 7" /etc/redhat-release` ]]; then
      print_error "This build script is tested on RHEL 7. Please update via yum or use the proper version."
      exit 0
    fi
  fi
 
  # Make sure that we are running on RHEL or Centos
  if [[ ! -f /etc/redhat-release && ! -f /etc/centos-release ]]; then
    print_error "I'm sorry, this distibution is not supported."
    exit 0
  fi   

  # Make sure that there are no kernel updates.
  if [[ -z `yum check-update | grep kernel` ]]; then
    print_good "Kernel appears to be up to date."
  else
    print_error "You appear to have kernel updates available. Please update via yum, reboot and run this script again."
    exit 0 
  fi

  # Warn the user if we are not installing on the newest kernel version
  newest_kernel=$(rpm -q --last kernel | perl -pe 's/^kernel-(\S+).*/$1/' | head -1)
  current_kernel=$(uname -r)
  if [ ! $newest_kernel == $current_kernel ]; then
    print_error "It looks like you are not installing on the most recent kernel. Are you sure you don't want to reboot before you run this?"
    pause "Please press [ENTER] to continue or CTRL+C to quit."
  fi

  # Make sure epel is installed on centos
  if [ -f /etc/centos-release ]; then
    if [[ ! `yum repolist | grep epel | awk '{ print $1 }'` ]]; then
        print_status "Epel not found, installing epel..."
        sudo yum -y install epel-release
        handle_error
    fi
  fi

  # Make sure net-tools is installed on centos for ifconfig
  if [ -f /etc/centos-release ]; then
    if [[ ! `yum list installed | grep net-tools | awk '{ print $1 }'` ]]; then
        print_status "net-tools not found, installing for ifconfig..."
        sudo yum -y install net-tools
        handle_error
    fi
  fi
  
  # Check to make sure that the user that we are running as and dropping permissions to exists
  if id -u "$user_drop" >/dev/null 2>&1; then
    print_good "user $user_drop exists"
  else
    print_error "The user \"$user_drop\" does not exist. Please create the user or select and different user and run again."
    exit 0
  fi
 
  # Check to see that the first character of wrk_dir and install_dir are / and that the last is not a /
  if [[ `echo $wrk_dir | head -c 1` != "/" ]]; then
    print_error "It looks like you dont have a / as the first character in the wrk_dir variable. Full path please."
    exit 0
  fi
  if [[ `echo $install_dir | head -c 1` != "/" ]]; then
    print_error "It looks like you dont have a / as the first character in the install_dir variable. Full path please."
    exit 0
  fi
  if [ `echo ${install_dir: -1} == "/"` ]; then
    print_error "It looks like you included a trailing / in the install_dir variable, remove that."
    exit 0
  fi
  if [ `echo ${wrk_dir: -1} == "/"` ]; then
    print_error "It looks like you included a trailing / in the wrk_dir variable, remove that."
    exit 0
  fi

  #Check to see that timezone is set to UTC
  if [[ -z `date | grep UTC` ]]; then
    print_error "Looks like UTC isnt set. You want this."
    rm -rf /etc/localtime
    ln -f -s /usr/share/zoneinfo/UTC /etc/localtime
  fi

  # Check to see that root umask 022 at login
  if [[ -z `cat /root/.bashrc | grep 022` ]]; then
    print_error "Root needs umask 022"
    echo -e "umask 022" >> /root/.bashrc
    source /root/.bashrc
    umask 022
    if [[ $(umask) != 0022 ]]; then
     print_error "IDK. Something didnt work."
     exit 0
    fi
  fi
  
  # Make sure swap is off
  swapoff -a
  if [[ -z `crontab -l | grep swapoff` ]]; then
    print_error "Swap is not disabled at boot, fixing."
    line_swapoff="@reboot swapoff -a"
    (crontab -l; echo "$line_swapoff") | crontab -
    handle_error
  fi

  # Add unlimited memlock
  if [[ -z `cat /etc/security/limits.conf | grep -E 'memlock.*unlimited'` ]]; then
    print_error "Memlock is not set to unlimited, fixing."
    echo -e "*               -       memlock                 unlimited" >> /etc/security/limits.conf
  fi
 
  #Check to see that the sniffing ethernet port is up and configured properly
  if [[ $sniff_int != $manage_int ]]; then
    if [[ -z `ifconfig | grep $sniff_int` ]]; then
      print_error "Looks like the interface isnt configured..."
      sed -i 's/ONBOOT=no/ONBOOT=yes/' /etc/sysconfig/network-scripts/ifcfg-$sniff_int
      sed -i 's/BOOTPROTO=dhcp/BOOTPROTO=static/' /etc/sysconfig/network-scripts/ifcfg-$sniff_int
      echo -e "PROMISC=yes" >> /etc/sysconfig/network-scripts/ifcfg-$sniff_int
      echo -e "IPV6INIT=no" >> /etc/sysconfig/network-scripts/ifcfg-$sniff_int
      echo -e "PEERDNS=no" >> /etc/sysconfig/network-scripts/ifcfg-$sniff_int 
      service network restart
      ifconfig $sniff_int promisc
      ethtool -G $sniff_int rx 4096  #Add this to crontab @reboot
      ifconfig $sniff_int txqueuelen 10000
    fi
  else
    ifconfig $sniff_int promisc
    ethtool -G $sniff_int rx 4096  #Add this to crontab @reboot
    ifconfig $sniff_int txqueuelen 10000
  fi

  # Kernel Tuning
  # http://pevma.blogspot.com/2014/03/suricata-prepearing-10gbps-network.html
  if [[ -z `cat /etc/sysctl.conf | grep net.core.netdev_max_backlog=250000` ]]; then
    echo 'net.core.netdev_max_backlog=250000' >> /etc/sysctl.conf
    echo 'net.core.rmem_max=16777216' >> /etc/sysctl.conf
    echo 'net.core.rmem_default=16777216' >> /etc/sysctl.conf
    echo 'net.core.optmem_max=16777216' >> /etc/sysctl.conf
    sysctl -p 
  fi

  #Check to see if we need to deal with a proxy and make sure it starts with http
  if [ -z $proxy_ip ]; then
    proxy_status=false
  else 
    proxy_status=true
    if [[ -z `echo $proxy_ip | grep http` ]]; then
      print_error "The proxy IP needs to begin with http, please change it."
      exit 0
    fi
  fi

  #Check to see that all the global variables are properly set 
  if [[ -z "$sniff_int" || -z "$manage_int" || -z "$manage_ip" || -z "$user_drop" || -z "$wrk_dir" || -z "$install_dir" || -z "$proxy_status" || -z "$num_bro_pf_proc" || -z "$pf_num_rings" || -z "$pf_trans_mode" ]]; then
    print_error "You must set the mandatory global variables."
    exit 0
  fi

  #Check to see if we're using ETPro or ET Community sigs
  if [[ -z "$etpro_license" ]]; then
    et_status="ET Community Ruleset"
  else
    et_status="ET PRO Ruleset"
  fi

  #Check to see if we're installing moloch
  if [[ $launch_param == "-ro" || $launch_param == "-moloch" ]]; then
    moloch_me_maybe=true
    if [[ -z "$es_mem" || -z "$moloch_user" ||  -z "$moloch_password" || -z "$moloch_group" || -z "$moloch_fqdn" || -z "$moloch_country" || -z "$moloch_state" || -z "$moloch_orgname" || -z "$moloch_orgunit" || -z "$moloch_locality" || -z "$es_ver" || -z "$esdb_dir" || -z "$pcap_data_dir" ]]; then
      print_error "You appear to be installing moloch and have not properly set all the variables."
      exit 0
    fi
  fi

  #Check to see if we've properly set log aggregation variables...
  if [[ $launch_param == "-ro" || $launch_param == "-logagg" ]]; then  
    if [ -z $log_method ]; then
      print_error "Make sure you've set the log_method global variable."
      exit 0
    fi
    if [[ $log_method != "logstash_elasticsearch" && $log_method != "logstash_syslog" && $log_method != "splunk" ]]; then
      print_error "Make sure you've selected one of the log aggregation options. Make sure there are no typos. :)"
    fi    
    if [[ -z $splunk_bro_index || -z $splunk_suricata_index ]]; then
      print_error "Make sure you've set the log aggregation index variables for bro and suricata."
      exit 0
    fi
    if [[ $log_method == "splunk" ]]; then
      if [ -z $splunk_fwd ]; then
        print_error "Since you selected to use splunk log aggregation, you need to set the splunk_fwd variable."
        exit 0
      fi
    fi
    if [[ $log_method == "logstash_elasticsearch" ]]; then
      if [ -z $logstash_elasticsearch_host ]; then
        print_error "Since you selected to use the logstash_elasticsearch log aggregation, you need to set the logstash_elasticsearch_host global variable to tell us where to send logs."
        exit 0
      fi
    fi
    if [[ $log_method == "logstash_elasticsearch" ]]; then
      if [ -z $logstash_elasticsearch_port ]; then
        print_error "Since you selected to use the logstash_elasticsearch log aggregation, you need to set the logstash_elasticsearch_port global variable to tell us where to send logs."
        exit 0
      fi
    fi
    if [[ $log_method == "logstash_syslog" ]]; then
      if [ -z $logstash_syslog_ip ]; then
        print_error "Since you selected to use logstash_syslog log aggregation, you need to set the logstash_syslog_ip variable so we know where to send syslog."
        exit 0
      fi
    fi
    if [[ $log_method == "logstash_syslog" ]]; then
      if [ -z $logstash_syslog_port ]; then
        print_error "Since you selected to use logstash_syslog log aggregation, you need to set the logstash_syslog_port variable so we know where to send syslog."
        exit 0
      fi
    fi
    if [[ $log_method == "logstash_syslog" ]]; then
      if [ -z $logstash_syslog_protocol ]; then
        print_error "Since you selected to use logstash_syslog log aggregation, you need to set the logstash_syslog_protocol variable so we know what protocol to send syslog on."
        exit 0
      fi
    fi
  fi

  # Check to see that NTOP repo is there, if not, write it
    cat << EOF > /etc/yum.repos.d/ntop.repo
[ntop]
name=ntop packages
baseurl=http://packages.ntop.org/centos-stable/7Server/x86_64/
enabled=1
#proxy=$proxy_ip:$proxy_port
gpgcheck=1
gpgkey=http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri
[ntop-noarch]
name=ntop packages
baseurl=http://packages.ntop.org/centos-stable/7Server/noarch/
enabled=1
#proxy=$proxy_ip:$proxy_port
gpgcheck=1
gpgkey=http://packages.ntop.org/centos-stable/RPM-GPG-KEY-deri
EOF
    if [ $proxy_status == true ]; then
        sed -i "s/#proxy=/proxy=/" /etc/yum.repos.d/ntop.repo
    fi

  # set proxies if needed  
    if [ $proxy_status == true ]; then

     #Normal proxy stuff (wget, curl, yum)
     HTTP_PROXY=$proxy_ip":"$proxy_port
     http_proxy=$proxy_ip":"$proxy_port
     HTTPS_PROXY=$proxy_ip":"$proxy_port
     https_proxy=$proxy_ip":"$proxy_port
     ftp_proxy=$proxy_ip":"$proxy_port
     export http_proxy https_proxy ftp_proxy HTTP_PROXY HTTPS_PROXY

     #GIT proxy stuff
     git config --global http.proxy $proxy_ip:$proxy_port
     git config --global https.proxy $proxy_ip:$proxy_port
     
     #NPM proxy stuff
     #npm config set proxy $proxy_ip:$proxy_port
     #npm config set https-proxy $proxy_ip:$proxy_port
    fi

  # Set build param variables based on launch param
  if [ $launch_param == "-ro" ]; then
     build_param="Red Onion"
  elif [ $launch_param == "-bro" ]; then
     build_param="Bro"
  elif [ $launch_param == "-moloch" ]; then
     build_param="Moloch"
  elif [ $launch_param == "-suricata" ]; then
     build_param="Suricata"
  elif [ $launch_param == "-pfring" ]; then
     build_param="Pfring"
  elif [ $launch_param == "-logagg" ]; then
     build_param="Log Aggregation"
  else
     build_param="Red Onion"
  fi

 # Check to see if a pfring enabled driver is enabled on the sniffing interface.
  sniff_driver=$(ethtool -i $sniff_int | grep driver | awk '{ print $2 }')
    if [[ $sniff_driver == "igb" || $sniff_driver == "ixgbe" || $sniff_driver == "e1000e" ]]; then
      pfring_zc_enabled=true
    else
      pfring_zc_enabled=false
      print_error "Your server doesnt appear have a pfring supported nic, you are using $sniff_driver."
      print_error "We will continue to build, but you may see issues at large capture rates without a pfring supported nic." 
    if [ $pf_trans_mode != 0 ]; then
       print_error "You need to set the pf_trans_mode global variable to 0 as you are not using a pfring supported nic."
       exit 0
     fi
    fi

#Print build debugging statement to show all the variables set
  echo -e ""
  print_good "I will now be building \x1B[01;31m$build_param\x1B[0m on $distro with the following specifications:"
  echo -e ""
  
  # General build stuff
  print_status "Working directory: $wrk_dir"
  print_status "Installation directory: $install_dir"
  print_status "Sniffing interface: $sniff_int"
  print_status "Management interface: $manage_int"
  print_status "Management IP Address: $manage_ip"
  print_status "Drop permissions to: $user_drop"
  print_status "Proxy status: $proxy_status"

  # Bro
  if [[ $launch_param == "-ro" || $launch_param == "-bro" ]]; then
    print_status "BRO pfring load balancers: $num_bro_pf_proc"
  fi
  
  # Pfring
  if [[ $launch_param == "-ro" || $launch_param == "-pfring" ]]; then
    print_status "Pfring number of rings: $pf_num_rings"
    print_status "Pfring transparent mode: $pf_trans_mode"
  fi

  # Log Aggregation
  if [[ $launch_param == "-ro" || $launch_param == "-logagg" ]]; then
    print_status "Log Aggregation: $log_method"
    if [[ $log_method == "splunk" ]]; then
      print_status "Splunk Forwarder IP: $splunk_fwd"
      print_status "Bro Index Name: $bro_index"
      print_status "Suricata Index Name: $suricata_index"    
    elif [[ $log_method == "logstash_elasticsearch" ]]; then
      print_status "Log Aggregation Elasticsearch Host: $logstash_elasticsearch_host"
      print_status "Log Aggregation Elasticsearch Port: $logstash_elasticsearch_port"
    elif [[ $log_method == "logstash_syslog" ]]; then
      print_status "Syslog Receiver IP: $logstash_syslog_ip"
      print_status "Syslog Receiver Port : $logstash_syslog_port"
      print_status "Syslog Receiver Protocol: $logstash_syslog_protocol"
    fi
  fi

  # ETPRO
  if [[ $launch_param == "-ro" || $launch_param == "-suricata" ]]; then
    print_status "EmergingThreats License: $et_status"
  fi

  # Moloch
  if [[ $moloch_me_maybe == true ]]; then
    print_status "Memory Allocated to ES: $es_mem"
    print_status "Elasticsearch Version: $es_ver"
    print_status "Elasticsearch DB Location: $esdb_dir"
    print_status "Raw Pcap Storage Location: $pcap_data_dir"
    print_status "Moloch User: $moloch_user"
    print_status "Moloch Group: $moloch_group"
    print_status "Moloch Password: $moloch_password"
    print_status "Moloch FQDN: $moloch_fqdn"
    print_status "Moloch Country: $moloch_country"
    print_status "Moloch State: $moloch_state"
    print_status "Moloch Org Name: $moloch_orgname"
    print_status "Moloch Org Unit: $moloch_orgunit"
    print_status "Moloch Locality: $moloch_locality"
  fi
  
  # Date
  print_status "Current Date: $(date)" 
  echo -e ""

  pause "Please verify the above settings and press [ENTER] to continue or CTRL+C to quit."

}

function pf_ring_rpm ()
{
 
  space_pls
  print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!"
  print_status "!!! Installing PF_RING !!!"
  print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!"
  space_pls

  # Install prereqs
  if [ -f /etc/centos-release ]; then
    yum -y install numactl-devel vim-enhanced wget kernel-headers flex bison gcc gcc-c++ make kernel-devel man man-pages screen htop 
  fi

  sniff_driver=$(ethtool -i $sniff_int | grep driver | awk '{ print $2 }')
  if [[ $sniff_driver == "igb" || $sniff_driver == "e1000e" || $sniff_driver == "ixgbe" ]]; then
    pfring_zc_enabled=true
  else
    pfring_zc_enabled=false
  fi

  # Check to see if we want to install...
  SKIP=0
  if [ -d "$install_dir/pfring/kernel" ]; then
    print_error "It looks like pfring may already be downloaded, do you want to install it again? (y/n): "
    read answer
    if [[ $answer == "y" ]] ; then
      print_status "Pulling pfring src from Github"
      git clone -b 6.0.3-stable https://github.com/ntop/PF_RING $install_dir/pfring
      handle_error
      SKIP=0
    else
      SKIP=1
    fi
  else
    print_status "Pulling pfring src from Github"
    git clone https://github.com/ntop/PF_RING $install_dir/pfring
    handle_error
  fi

  if [[ $SKIP == 0 ]]; then
    # Compile Kernel Module
    print_status "cd $install_dir/pfring/kernel..."
    cd $install_dir/pfring/kernel
    handle_error
    print_status "chown -R $user_drop:$user_drop $install_dir/pfring/..."
    chown -R $user_drop:$user_drop $install_dir/pfring/
    handle_error
    if [ $pfring_zc_enabled == true ]; then
      print_status "yum clean all"
      yum clean all 
      handle_error
      print_status "yum update"
      yum update 
      handle_error
      print_status "yum install pfring dkms stuff via ntop repo"
      yum -y install pfring pfring-drivers-zc-dkms igb-zc 
      handle_error
      dkms status
      sleep 10
    else
      print_status "yum clean all"
      yum clean all 
      handle_error
      print_status "yum update"
      yum update 
      handle_error
      print_status "yum install pfring"
      yum -y install pfring 
      handle_error
      dkms status
      sleep 10   
    fi
    # Compile Userland Libraries
    print_status "Compiling userland libraries..."
    print_status "cd ../userland/lib..."
    cd ../userland/lib
    handle_error
    print_status "./configure --prefix=/usr/local/pfring..."
    ./configure --prefix=/usr/local/pfring 
    handle_error
    print_status "make clean..."
    make clean 
    handle_error
    print_status "make..."
    make 
    handle_error
    print_status "make install..."
    make install 
    handle_error

    # Build Libpcap - libpcap is lnk to the numbered version in the same dir...
    print_status "Building libpcap..."
    print_status "cd ../libpcap..."
    cd ../libpcap
    handle_error
    print_status "./configure --prefix=/usr/local/pfring..."
    ./configure --prefix=/usr/local/pfring 
    handle_error
    print_status "make clean..."
    make clean 
    handle_error
    print_status "make..."
    make 
    handle_error
    print_status "make install..."
    make install 
    handle_error

    # Build tcpdump
    print_status "Building tcpdump..."
    print_status "cd ../tcpdump-4.9.0..."
    cd ../tcpdump-4.9.0
    handle_error
    print_status "./configure --prefix=/usr/local/pfring..."
    ./configure --prefix=/usr/local/pfring 
    handle_error
    print_status "make clean..."
    make clean 
    handle_error
    print_status "make..."
    make 
    handle_error
    print_status "make install..."
    make install 
    handle_error
    ldconfig
    handle_error

    # Load Kernel Module
    print_status "Loading kernel module..."
    print_status "modprobe pf_ring..."
    modprobe pf_ring transparent_mode=$pf_trans_mode enable_tx_capture=0 min_num_slots=$pf_num_rings
    handle_error
    lsmod | grep pf_ring
    sleep 10

    # Configure Linker
    print_status "Configuring linker..."
    echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig
    handle_error

    # Load at boot
    print_status "Setting up persistance..."
    print_status "modprobe pf_ring...set options..."
    echo "modprobe pf_ring transparent_mode=$pf_trans_mode enable_tx_capture=0 min_num_slots=$pf_num_rings" > /etc/sysconfig/modules/pf_ring.modules
    handle_error
    if [ $pfring_zc_enabled == true ]; then
      print_status "echo "modprobe ${sniff_driver}_zc" >> /etc/sysconfig/modules/pf_ring.modules..."
      echo "modprobe ${sniff_driver}_zc" >> /etc/sysconfig/modules/pf_ring.modules
      handle_error
    fi
    print_status "chmod +x /etc/sysconfig/modules/pf_ring.modules..."
    chmod +x /etc/sysconfig/modules/pf_ring.modules
    handle_error
    if [ $pfring_zc_enabled == true ]; then
      print_status "fixing up /etc/modprobe.d/pfring-zc.conf for reboot so that it loads the right igb-zc driver instead of igb..."
      sed -i "s,$sniff_driver-zc,$sniff_driver," /etc/modprobe.d/pfring-zc.conf
      handle_error
    fi

    # Enable NIC driver if needed
    if [ $pfring_zc_enabled == true ]; then
      print_status "Unloading nic driver for sniffing interface...assuming $sniff_driver..."
      rmmod $sniff_driver
      handle_error
      modprobe ${sniff_driver}_zc
      handle_error
      lsmod | grep pf_ring
      lsmod | grep ${sniff_driver}_zc
      sleep 10
    fi
  
    print_status "moving back to the working dir..."
    cd $wrk_dir
    handle_error
  else
    space_pls
    print_good "Skipped PF_RING install..."
  fi

  space_pls
  print_status "PF_RING install has completed."
  space_pls

}

function bro () 
{

  print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!"
  print_status "!!!!! Installing BRO !!!!!"
  print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!"
  space_pls

  sniff_driver=$(ethtool -i $sniff_int | grep driver | awk '{ print $2 }')
  if [[ $sniff_driver == "igb" || $sniff_driver == "e1000e" || $sniff_driver == "ixgbe" ]]; then
    pfring_zc_enabled=true
  else
    pfring_zc_enabled=false
  fi

  SKIP=0
  if [ -d "$install_dir/bro/bin" ]; then
    print_error "It looks like bro may already be installed...do you want to install it again? (y/n): "
    read answer
    if [[ $answer == "y" ]]; then
      print_status "Proceeding to re-install bro..."
    else
      SKIP=1
    fi
  else
    print_status "Proceeding to install bro..."
  fi

  if [[ $SKIP == 0 ]]; then
    
    # Prereqs
    if [ -f /etc/centos-release ]; then
      print_status "installing prereqs via yum..."
      yum -y install cmake make gcc gcc-c++ flex bison openssl-devel python-devel swig zlib-devel file-devel geoip-devel sendmail libpcap-devel screen htop 
    fi
  
    #decompress, cd to source
    cd $wrk_dir
    wget "https://www.bro.org/downloads/release/bro-2.4.1.tar.gz"
    handle_error
    tar xzf bro-2.4.1.tar.gz
    handle_error
    cd bro-2.4.1/
    handle_error

    #install bro
    print_status "./configure --prefix=$install_dir/bro/ --with-pcap=/usr/local/pfring..."
    export LDFLAGS="-Wl,--no-as-needed -lrt" 
    export LIBS="-lrt -lnuma" 
    ./configure --prefix=$install_dir/bro/ --with-pcap=/usr/local/pfring 
    handle_error
    print_status "make clean..."
    make clean 
    handle_error
    print_status "make...(bro takes a while to make)"
    make 
    handle_error
    print_status "make install..."
    make install 
    handle_error
    print_status "Building BRO config based on global vars..."
    sed -i 's,interface=eth0,#interface=eth0,' $install_dir/bro/etc/node.cfg
    echo -e "[manager]\ntype=manager\nhost=$manage_ip\n\n" >> $install_dir/bro/etc/node.cfg
    handle_error
    echo -e "[proxy-1]\ntype=proxy\nhost=$manage_ip\n\n" >> $install_dir/bro/etc/node.cfg
    handle_error
    echo -e "[worker-1]\ntype=worker\nhost=$manage_ip\ninterface=$sniff_int\nlb_method=pf_ring\nlb_procs=$num_bro_pf_proc" >> $install_dir/bro/etc/node.cfg
    handle_error
    sed -i 's/\[bro\]/#\[bro\]/' $install_dir/bro/etc/node.cfg  
    handle_error
    sed -i 's/type=standalone/#type=standalone/' $install_dir/bro/etc/node.cfg
    handle_error
    sed -i 's/host=localhost/#host=localhost/' $install_dir/bro/etc/node.cfg
    handle_error
    print_status "Ok, here's the config file for bro..."
    cat $install_dir/bro/etc/node.cfg
    sleep 10
    
    if [ $pfring_zc_enabled == "true" ]; then
     print_status "Checking to make sure bro compiled with pfring properly..."
     if [[ -z `ldd $install_dir/bro/bin/bro | grep pfring` ]]; then
       print_error "It looks like bro didnt properly link libpcap...here look:"
       ldd $install_dir/bro/bin/bro | grep libpcap
       print_error "That should point to '/usr/local/pfring/lib/libpcap.so.1'"
       print_error "You will need to make sure pfring installed properly and that bro is properly searching for the so."
       exit 0
     else
       print_good "Looks good."
       ldd $install_dir/bro/bin/bro | grep libpcap
     fi
    fi
     
    print_status "cleanup..."
    rm -rf $wrk_dir/bro-2.4.1
    handle_error
    $install_dir/bro/bin/broctl cron enable
    handle_error
    $install_dir/bro/bin/broctl install
    handle_error
    $install_dir/bro/bin/broctl check
    handle_error
    print_status "adding broctl cron..."
    line_bro="0-59/5 * * * *    $install_dir/bro/bin/broctl cron"
    (crontab -l; echo "$line_bro" ) | crontab -
    sed -i "s,/var/opt/bro/spool,${install_dir}/bro/spool," $install_dir/bro/etc/broctl.cfg
    handle_error
    sed -i "s,/var/opt/bro/logs,${install_dir}/bro/logs," $install_dir/bro/etc/broctl.cfg
    handle_error
    print_status "moving back to the working dir..."
    cd $wrk_dir
    handle_error
    
  else
    space_pls
    print_good "Skipped BRO install..."
  fi

  space_pls
  print_status "BRO install has completed."
  space_pls

}

function suricata () 
{

  print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  print_status "!!!!! Installing Suricata !!!!!"
  print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  space_pls

  sniff_driver=$(ethtool -i $sniff_int | grep driver | awk '{ print $2 }')
  if [[ $sniff_driver == "igb" || $sniff_driver == "e1000e" || $sniff_driver == "ixgbe" ]]; then
    pfring_zc_enabled=true
  else
    pfring_zc_enabled=false
  fi

  SKIP=0
  if [ -d "$install_dir/suricata/bin" ]; then
    print_error "It looks like suricata may already be installed...do you want to install it again? (y/n): "
    read answer
    if [[ $answer == "y" ]]; then
      print_status "Proceeding to re-install suricata..."
      print_status "Moving the suricata folder to old_suricata..."
      mv $install_dir/suricata $install/old_suricata
      print_status "Removing lua .so's so they can be rebuilt..."
      rm -f /usr/lib64/lua/5.1/zip.so 
      rm -f /usr/lib64/lua/5.1/apr 
      rm -f /usr/lib64/lua/5.1/ltn12ce 
      rm -f /usr/lib64/lua/5.1/zlib.so 
      rm -f /usr/lib64/lua/5.1/struct.so
      print_status "Removing decompressed lua thirdparty modules so they can be rebuilt..."
      rm -f $wrk_dir/lua_stuff
    else
      SKIP=1
    fi
  else
    print_status "Proceeding to install suricata..."
  fi

  if [[ $SKIP == 0 ]]; then

    # Prereqs
    if [ -f /etc/centos-release ]; then
      yum -y install libpcap libpcap-devel libnet libnet-devel pcre pcre-devel gcc gcc-c++ automake autoconf screen htop libtool make libyaml libyaml-devel zlib zlib-devel file-devel wget git-core nss-util nss-util-devel nss-devel nspr-devel nspr GeoIP-devel GeoIP python-simplejson python-setuptools python-instant python-distutils-extra 
    fi

    # Lua scripting support
    if [ -f /etc/centos-release ]; then
      yum install -y zip unzip cmake lua-devel apr-devel apr-util-devel libapreq2 libapreq2-devel zziplib zziplib-devel 
    fi

    print_status "Decompressing Lua Thirdparty Modules"
    mkdir $wrk_dir/lua_stuff
    tar xzf $wrk_dir/lua_thirdparty.tar.gz -C $wrk_dir/lua_stuff

    # no luarocks in epel 7 have to build
    cd $wrk_dir/lua_stuff
    wget "http://luarocks.org/releases/luarocks-2.2.2.tar.gz"
    tar -xzpf luarocks-2.2.2.tar.gz
    cd luarocks-2.2.2
    ./configure --with-lua=/usr
    make build
    make install

    # PCRE
    cd $wrk_dir/lua_stuff
    handle_error
    tar -xzvf pcre-8.35.tar.gz
    handle_error
    cd pcre-8.35
    handle_error
    ./configure --prefix=/usr/local/pcre-8.35/ --enable-jit --enable-utf8 --enable-unicode-properties
    handle_error
    make -j 
    handle_error
    make install 
    handle_error
    cd ..

    /usr/local/bin/luarocks install struct 
    handle_error
    /usr/local/bin/luarocks install lua-apr 
    handle_error
    /usr/local/bin/luarocks install luazip 
    handle_error

    # LUA ZLIB
    mkdir lua-zlib
    handle_error
    cd lua-zlib
    handle_error
    unzip $wrk_dir/lua_stuff/lua-zlib.zip
    handle_error
    cmake lua-zlib 
    handle_error
    make install 
    handle_error
    cd ..
    handle_error

    # ltn12ce
    unzip ltn12ce.zip
    handle_error
    cd ltn12ce
    handle_error
    mkdir build 
    handle_error
    cd build
    handle_error
    cmake .. -DBUILD_ZLIB=Off 
    handle_error
    make 
    handle_error
    make install 
    handle_error
    cd ..
    handle_error

    # LuaBitOp
    cd $wrk_dir/lua_stuff
    handle_error
    tar xzf LuaBitOp-1.0.2.tar.gz
    handle_error
    cd LuaBitOp-1.0.2
    handle_error
    make 
    handle_error
    make install 
    handle_error

    # Links so lua can find things where it expects them
    ln -s /usr/lib/lua/5.1/zip.so /usr/lib64/lua/5.1/zip.so
    handle_error
    ln -s /usr/lib/lua/5.1/apr /usr/lib64/lua/5.1/apr
    handle_error
    ln -s /usr/local/lib/lua/ltn12ce /usr/lib64/lua/5.1/ltn12ce 
    handle_error
    ln -s /usr/local/share/lua/cmod/zlib.so /usr/lib64/lua/5.1/zlib.so
    handle_error
    ln -s /usr/lib/lua/5.1/struct.so /usr/lib64/lua/5.1/struct.so
    handle_error

    rm -rf $wrk_dir/lua_stuff
    handle_error
    
    # Uncompress Suri install files
    cd $wrk_dir
    wget "http://www.openinfosecfoundation.org/download/suricata-2.0.10.tar.gz"
    handle_error
    tar xzf suricata-2.0.10.tar.gz
    handle_error
    print_status "cd suricata-2.0.8/..."
    cd suricata-2.0.10/
    handle_error

    print_status "Installing suri...wooo..."
    print_status "big configure statement w/ pfring stuff..."
    LIBS=-lrt ./configure --prefix=$install_dir/suricata/ --enable-pfring --enable-lua --with-libpfring-includes=/usr/local/pfring/include --with-libpfring-libraries=/usr/local/pfring/lib --with-libpcap-includes=/usr/local/pfring/include --with-libpcap-libraries=/usr/local/pfring/lib 
    handle_error
    print_status "make clean..."
    make clean 
    handle_error
    print_status "make..."
    make 
    handle_error
    print_status "make install-full..."
    make install-full 
    handle_error
    print_status "ldconfig..."
    ldconfig
    handle_error

    # Oinkmaster

    print_status "Copy over oinkmaster for updating..."
    tar xzf $wrk_dir/oinkmaster.tar.gz -C $install_dir
    handle_error

    # Configure etpro ruleset if set

    if [ -z $etpro_license ]; then 
      print_status "Using Emerging Threats Community Ruleset"
    else
      print_status "sed -i 's/url = http:\/\/rules.emergingthreats.net\/open\/suricata\/emerging.rules.tar.gz/url = http:\/\/rules.emergingthreatspro.com\/$etpro_license\/suricata-1.3\/etpro.rules.tar.gz/' $install_dir/oinkmaster/oinkmaster.conf..."
      sed -i "s,url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz,url = http://rules.emergingthreatspro.com/$etpro_license/suricata-1.3/etpro.rules.tar.gz," $install_dir/oinkmaster/oinkmaster.conf
      handle_error
    fi

    # Get Rules / Configure Cron

    print_status "update ruleset with ET sigs..."
    $install_dir/oinkmaster/oinkmaster.pl -C $install_dir/oinkmaster/oinkmaster.conf -o $install_dir/suricata/etc/suricata/rules/ 
    handle_error
    print_status "grab the et-luajit-rules..."
    git clone https://github.com/EmergingThreats/et-luajit-scripts $install_dir/suricata/et-luajit-scripts 
    handle_error
    cp $install_dir/suricata/et-luajit-scripts/* $install_dir/suricata/etc/suricata/rules/
    handle_error

    # Add Crontab that will update sigs and reload suri every 12 hours...

    cat << EOF > $install_dir/suricata/ruleupdates.sh
#!/bin/sh
$install_dir/oinkmaster/oinkmaster.pl -C $install_dir/oinkmaster/oinkmaster.conf -o $install_dir/suricata/etc/suricata/rules/
cd $install_dir/suricata/et-luajit-scripts/
git pull
cp $install_dir/suricata/et-luajit-scripts/* $install_dir/suricata/etc/suricata/rules/
EOF

    chmod +x $install_dir/suricata/ruleupdates.sh
    print_status "add crontab to update sigs and reload suri every 12 hours..."
    line_suri="0 */12 * * *  $install_dir/suricata/ruleupdates.sh && /etc/init.d/suricata reload"
    (crontab -l; echo "$line_suri" ) | crontab -
    handle_error

    # Copy init.d script

    print_status "copy over init.d script to /etc/init.d/suricata..."
    cp $wrk_dir/config/suricata/suricata.startup /etc/init.d/suricata
    chmod +x /etc/init.d/suricata
    handle_error
    sed -i "s,daemon suricata -c \/etc\/suricata.yaml -i eth0,daemon $install_dir\/suricata\/bin\/suricata --pfring-int=$sniff_int --pfring-cluster=99 --pfring-cluster-type=cluster_flow -D -c $install_dir\/suricata\/etc\/suricata\/suricata.yaml," /etc/init.d/suricata
    handle_error

    # Copy over preconfigured yaml and fixup config file for sniffing int
    cp $wrk_dir/conf/suricata/suricata.yaml $install_dir/suricata/etc/suricata/
    sed -i "s,  - interface: eth0,  - interface: $sniff_int," $install_dir/suricata/etc/suricata/suricata.yaml
    sed -i "s,/opt,$install_dir," $install_dir/suricata/etc/suricata/suricata.yaml 
    sed -i "s,CHANGEME,${user_drop}," $install_dir/suricata/etc/suricata/suricata.yaml
    sed -i "s,/var/log/suricata.log,${install_dir}/suricata/var/log/suricata.log," $install_dir/suricata/etc/suricata/suricata.yaml

    # Copy over updated classification and reference file
    
    cd $install_dir/suricata/etc/suricata
    mv classification.config classification.config.old
    mv reference.config reference.config.old
    wget http://rules.emergingthreats.net/open/suricata-1.3/classification.config
    wget http://rules.emergingthreats.net/open/suricata-1.3/reference.config
   
   if [ $pfring_zc_enabled == "true" ]; then
    print_status "Checking to make sure Suricata compiled with pfring properly..."
    if [[ -z `ldd $install_dir/suricata/bin/suricata | grep pfring` ]]; then
      print_error "It looks like suricata didnt properly link libpfring...here look:"
      ldd $install_dir/suricata/bin/suricata | grep libpcap
      print_error "That should point to '/usr/local/pfring/lib/libpfring.so.1'"
      print_error "You will need to make sure pfring installed properly and that suricata is properly searching for the so."
      exit 0
    else
      print_good "Looks good."
      ldd $install_dir/suricata/bin/suricata | grep libpfring
    fi
   fi
 
    print_status "cleanup and moving back to working dir..."
    rm -rf $wrk_dir/suricata-2.0.8
    handle_error
    cd $wrk_dir
    handle_error
  else
    print_good "Skipped Suricata install..."
  fi
  print_status "Suricata install has completed."
}

function moloch () 
{

print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
print_status "!!!!! Installing Moloch !!!!!"
print_status "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
space_pls

SKIP=0
if [ -d "$install_dir/moloch/bin" ]; then
  print_error "It looks like moloch may already be installed...do you want to install it again? (y/n): "
  read answer
  if [[ $answer == "y" ]]; then
    print_status "Proceeding to re-install moloch..."
  else
    SKIP=1
  fi
else
  print_status "Proceeding to install moloch..."
fi

if [[ $SKIP == 0 ]]; then
  umask 022

  if [ -d "$wrk_dir/moloch/" ]; then
    print_status "using src found in $wrk_dir/moloch..."
  else
    print_status "Getting moloch from github with edits for redonion..."
    git clone https://github.com/hadojae/moloch 
    handle_error
  fi
  print_status "cd moloch..."
  cd moloch
  handle_error
  print_status "Fixup how much memory to give elasticsearch."
  sed -i "s,read ESMEM,ESMEM=${es_mem}," easybutton-singlehost.sh
  handle_error
  print_status "fixing up tdir in easybutton-singlehost.sh..."
  sed -i "s,TDIR=/data/moloch,TDIR=$install_dir/moloch," easybutton-singlehost.sh
  handle_error
  print_status "fixing up tdir in easybutton-build.sh..."
  sed -i "s,TDIR=CHANGEME,TDIR=$install_dir/moloch," easybutton-build.sh
  handle_error
  print_status "fixing up pfringdir in easybutton-build.sh..."
  sed -i "s,PFRINGDIR=CHANGEME,PFRINGDIR=$install_dir/pfring," easybutton-build.sh
  handle_error
  print_status "fixing up pcapdir in easybutton-build.sh..."
  sed -i "s,PCAPDIR=CHANGEME,PCAPDIR=$install_dir/pfring/userland/libpcap," easybutton-build.sh
  handle_error
  print_status "fixing up tdir in easybutton-config.sh..."
  sed -i "s,TDIR=CHANGEME,TDIR=$install_dir/moloch," easybutton-config.sh
  handle_error
  print_status "fixing up variables in easybutton-config.sh"
  sed -i "s,USERNAME=CHANGEME,USERNAME=${moloch_user}," easybutton-config.sh
  sed -i "s,GROUPNAME=CHANGEME,GROUPNAME=${moloch_group}," easybutton-config.sh
  sed -i "s,PASSWORD=CHANGEME,PASSWORD=${moloch_password}," easybutton-config.sh
  sed -i "s,INTERFACE=CHANGEME,INTERFACE=${sniff_int}," easybutton-config.sh
  sed -i "s,FQDN=CHANGEME,FQDN=${moloch_fqdn}," easybutton-config.sh
  sed -i "s,COUNTRY=CHANGEME,COUNTRY=${moloch_country}," easybutton-config.sh
  sed -i "s,STATE=CHANGEME,STATE=${moloch_state}," easybutton-config.sh
  sed -i "s,ORG_NAME=CHANGEME,ORG_NAME=${moloch_orgname}," easybutton-config.sh
  sed -i "s,ORG_UNIT=CHANGEME,ORG_UNIT=${moloch_orgunit}," easybutton-config.sh
  sed -i "s,LOCALITY=CHANGEME,LOCALITY=${moloch_locality}," easybutton-config.sh
  handle_error
  
  # fixup the singlehost script to use the right user
  sed -i "s,daemon:daemon,${user_drop}:${user_drop}," $wrk_dir/moloch/easybutton-singlehost.sh

  # I need to sed where the elasticsearch db is going to be stored in the elasticsearch yml
  sed -i "s,path.data: _TDIR_/data,path.data: $esdb_dir," $wrk_dir/moloch/single-host/etc/elasticsearch.yml
  
  # I need to sed where the raw pcap will be stored in the config.ini.template file
  sed -i "s,pcapDir = _TDIR_/raw,pcapDir = ${pcap_data_dir}," $wrk_dir/moloch/single-host/etc/config.ini.template
 
  print_status "Installing Moloch...this will take some time..."
  ./easybutton-singlehost.sh 
  handle_error

  print_status "going back to install dir..."
  cd $wrk_dir
  handle_error
  print_status "copying persistance script..."
  cp config/ro_persist.sh $install_dir
  sed -i "s,CHANGEESVER,${es_ver}," $install_dir/ro_persist.sh
  sed -i "s,CHANGEDIR,${install_dir}," $install_dir/ro_persist.sh
  sed -i "s,CHANGEESMEM,${es_mem}," $install_dir/ro_persist.sh
  sed -i 's/freeSpaceG = 600/freeSpaceG = 100/' $install_dir/moloch/etc/config.ini
  handle_error
  print_status "Opening up ports for moloch viewer and ES via iptables..."
  iptables -I INPUT -p tcp --dport 8005 -j ACCEPT
  handle_error
  service iptables save
  handle_error
  print_status "moloch db, capture, and viewer should all be up and running now..."
  ps aux | grep moloch
  sleep 10
  print_status "adding redonion persistance to crontab..."
  line_ro="#*/2 * * * *    $install_dir/ro_persist.sh >> $install_dir/crash.log 2>&1"
  (crontab -l; echo "$line_ro" ) | crontab -
  handle_error
  print_status "adding daily optimization script to crontab..."
  line_moloch_daily="@daily $install_dir/moloch/db/daily.sh > /dev/null 2>&1"
  (crontab -l; echo "$line_moloch_daily" ) | crontab -
  handle_error
  print_status "adding promisc to crontab for reboot..."
  line_promisc="@reboot ifconfig $sniff_int promisc"
  (crontab -l; echo "$line_promisc" ) | crontab -
  handle_error
  print_status "fixing up interface options..."
  for i in rx tx sg tso ufo gso gro lro; do ethtool -K $sniff_int $i off; done > /dev/null 2<&1
  handle_error
  print_status "adding nic feature disable to crontab..."
  line_fixup="@reboot for i in rx tx sg tso ufo gso gro lro; do ethtool -K $sniff_int \$i off; done > /dev/null 2<&1"
  (crontab -l; echo "$line_fixup" ) | crontab -
  handle_error
  print_status "Fixing up daily.sh..."
  sed -i "s,/data/moloch,$install_dir/moloch," $install_dir/moloch/db/daily.sh
  handle_error
  print_status "Stopping moloch-capture..."
  /usr/bin/pkill moloch
  handle_error
  print_status "Stopping moloch viewer..."
  /usr/bin/pkill node
  handle_error
  print_status "Stopping elasticsearch..."
  curl -XPOST localhost:9200/_shutdown
  handle_error
  print_status "Cleaning up..."
  rm -rf $wrk_dir/moloch
  handle_error

else
  print_good "Skipped installing Moloch..."
fi
}

function logagg ()
{

print_status "Fixing up selected logagg in ro_persist.sh..."
if [[ $log_method == "splunk" ]]; then
  sed -i "s,CHANGELOGAGG,splunk," $install_dir/ro_persist.sh
else
  sed -i "s,CHANGELOGAGG,logstash," $install_dir/ro_persist.sh
fi

if [ $log_method == "splunk" ]; then
 SKIP=0
 if [[ -d "$install_dir/splunkforwarder/bin" ]]; then
   print_error "It looks like splunk may already be installed...since i'm installing from rpm, i can't install till you remove it. Do you want to skip splunk install? (y/n): "
   read answer
   if [[ $answer == "y" ]]; then
     SKIP=1
   else
     print_error "Remove splunk forwarder via rpm -e and try again then."
   fi
 else
   print_status "Proceeding to install splunk forwarder..."
 fi

 if [[ $SKIP == 0 ]]; then
   print_status "Installing Splunk Universal Forwarder..."
   cd $wrk_dir/config/splunk
   wget -O splunkforwarder-6.2.2-255606-linux-2.6-x86_64.rpm 'http://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=Linux&version=6.2.2&product=universalforwarder&filename=splunkforwarder-6.2.2-255606-linux-2.6-x86_64.rpm&wget=true'
   # Check to see if splunk universal forwarder is already installed
   if [ -d "$install_dir/splunkforwarder/bin/splunk" ]; then
     print_error "It looks like splunk universal forwarder may already be installed...you will need to uninstall it first via rpm."
     rpm -ivh --prefix=$install_dir splunkforwarder-6.2.2-255606-linux-2.6-x86_64.rpm
     handle_error
   else
     print_status "Proceeding..."
   fi

  # install splunk forwarder via rpm
  print_status "Installing via rpm..."
  rpm -ivh --prefix=$install_dir splunkforwarder-6.2.2-255606-linux-2.6-x86_64.rpm
  handle_error

  # copy over premade config files to splunk
  cp inputs.conf $install_dir/splunkforwarder/etc/system/local/
  cp limits.conf $install_dir/splunkforwarder/etc/system/local/
  cp outputs.conf $install_dir/splunkforwarder/etc/system/local/
  cp props.conf $install_dir/splunkforwarder/etc/system/local/
  sed -i "s,CHANGEDIR,${install_dir}," $install_dir/splunkforwarder/etc/system/local/inputs.conf
  sed -i "s,CHANGEBRO,${splunk_bro_index}," $install_dir/splunkforwarder/etc/system/local/inputs.conf
  sed -i "s,CHANGESURI,${splunk_suricata_index}," $install_dir/splunkforwarder/etc/system/local/inputs.conf
  sed -i "s,CHANGEBRO,${splunk_bro_index}," $install_dir/splunkforwarder/etc/system/local/props.conf
  sed -i "s,CHANGESURI,${splunk_suricata_index}," $install_dir/splunkforwarder/etc/system/local/props.conf
  echo -e "server = $splunk_fwd" >> $install_dir/splunkforwarder/etc/system/local/outputs.conf

  # crontab @reboot
  line_splunk="@reboot $install_dir/splunkforwarder/bin/splunk start"
  (crontab -l; echo "$line_splunk" ) | crontab -
  handle_error

  #Cleanup and Done
  $install_dir/splunkforwarder/bin/splunk start
  print_good "Splunk installed"

 else
  print_status "Skipping splunk install..."
 fi

  #Cleanup and Done crontab @reboot
  line_splunk="@reboot $install_dir/splunk/bin/splunk start"
  (crontab -l; echo "$line_splunk" ) | crontab -
  handle_error
  rm -rf $wrk_dir/splunk
  print_good "Splunk installed"

 else
  print_status "Skipping splunk install..."
 fi
 
if [[ $log_method == logstash* ]]; then
 SKIP=0
 if [ `rpm -qa | grep logstash` ]; then
   print_error "It looks like Logstash may already be installed. Since i'm installing from rpm, i can't install till you remove it. Do you want to skip Logstash install? (y/n): "
   read answer
   if [[ $answer == "y" ]]; then
     SKIP=1
   else
     print_error "Remove logstash via rpm -e and try again then."
   fi
 else
   print_status "Proceeding to install Logstash..."
 fi

 if [[ $SKIP == 0 ]]; then
   print_status "Downloading and Installing Logstash into default directories..."
   cd $wrk_dir
   wget "https://download.elastic.co/logstash/logstash/packages/centos/logstash-2.1.0-1.noarch.rpm"
   handle_error
   print_status "Installing Logstash via rpm..."
   rpm -ivh logstash-2.1.0-1.noarch.rpm
   handle_error

   print_status "Copy over the config file"
   if [[ $log_method == logstash_elasticsearch ]]; then
     cp $wrk_dir/config/logstash/central_cluster.conf /etc/logstash/conf.d/central.conf
   elif [[ $log_method == logstash_syslog ]]; then
     cp $wrk_dir/config/logstash/central_cluster_syslog.conf /etc/logstash/conf.d/central.conf
   else
     print_error "Something went wrong copying the config file over..."
     exit 0
   fi

   print_status "Sed config params in the logstash conf file..."
   if [[ $log_method == logstash_elasticsearch ]]; then
     sed -i "s,CHANGEHOST,${logstash_elasticsearch_host}," /etc/logstash/conf.d/central.conf
     sed -i "s,CHANGEPORT,${logstash_elasticsearch_port}," /etc/logstash/conf.d/central.conf
     sed -i "s,CHANGEDIR,${install_dir}," /etc/logstash/conf.d/central.conf
   elif [[ $log_method == logstash_syslog ]]; then
     sed -i "s,CHANGEHOST,${logstash_syslog_ip}," /etc/logstash/conf.d/central.conf
     sed -i "s,CHANGEPORT,${logstash_syslog_port}," /etc/logstash/conf.d/central.conf
     sed -i "s,CHANGEPROTOCOL,${logstash_syslog_protocol}," /etc/logstash/conf.d/central.conf
     sed -i "s,CHANGEDIR,${install_dir}," /etc/logstash/conf.d/central.conf
   else
     print_error "Something went wrong seding the config file..."
     exit 0
   fi

   # additional packages needed for logstash syslog 
   if [[ $log_method == logstash_syslog ]]; then
     print_status "Installing logstash contrib packages for logstash syslog"
     cd $install_dir
     wget https://download.elastic.co/logstash/logstash/logstash-contrib-1.4.4.tar.gz
     handle_error
     tar xzf logstash-contrib-1.4.4.tar.gz
     handle_error
     yes | cp -rf logstash-contrib-1.4.4/* logstash > /dev/null
     handle_error
     rm -rf logstash-contrib-1.4.4 logstash-contrib-1.4.4.tar.gz
     handle_error
     cd $wrk_dir
   fi
     
   print_status "Crontab, Cleanup, and Done"
   line_logstash="@reboot service logstash start"
   (crontab -l; echo "$line_logstash" ) | crontab -
   handle_error
   rm -rf $wrk_dir/logstash-2.1.0-1.noarch.rpm
   print_good "Logstash installed"

 else
   print_status "Skipping logstash install..."
 fi
else
 exit 0
fi
}

function alldone ()
{
  print_good "Red Onion Install Complete."
  print_status "Do you want to start everything up now?: (y/n)"
  read answer
    if [[ $answer == "y" ]]; then
        print_status "Fixing up crontab for bro and persistence..."
        crontab -l | sed 's,#\*/2,\*/2,' | crontab -
        print_good "Persistence running, give it a few minutes and everything will be up and running."
        print_status "Please report any issues to https://github.com/hadojae/redonion"
        print_good "Thanks! :)"
        exit 0
    else
        print_status "Please report any issues to https://github.com/hadojae/redonion"
        print_good "Thanks! :)"
        exit 0
    fi
}

launch_param=$1

if [[ $1 == "-pfring" ]] ; then
  logo
  letsgo $launch_param
  pf_ring_rpm
  alldone
elif [[ $1 == "-bro" ]] ; then
  logo
  letsgo $launch_param
  bro
  alldone
elif [[ $1 == "-suricata" ]] ; then
  logo
  letsgo $launch_param
  suricata
  alldone
elif [[ $1 == "-moloch" ]] ; then
  logo
  letsgo $launch_param
  moloch
  alldone
elif [[ $1 == "-logagg" ]] ; then
  logo
  letsgo $launch_param
  logagg
  alldone
elif [[ $1 == "-ro" ]] ; then
  logo
  letsgo $launch_param
  pf_ring_rpm
  bro
  suricata
  moloch
  logagg
  alldone
else
    logo
    echo "This script attempts to streamline installation of tools required for Red Onion."
    echo ""
    echo "Usage: ./redonion_bootstrap.sh $param"
    echo ""
    echo "Optional Parameters: "
    echo ""
    echo "   -h  		Print this message"
    echo "   -ro  		Install Red Onion"
    echo "   -pfring  		Install only pfring"
    echo "   -bro  		Install only bro (requires pf_ring built)"
    echo "   -suricata  	Install only Suricata (requires pf_ring built)"
    echo "   -moloch  		Install only Moloch (requires pf_ring built)"
    echo "   -logagg  		Install only Log Aggregtion"
    echo ""
    echo "Questions / comments / improvements - https://github.com/hadojae/redonion"
    echo ""
    exit 0
fi
