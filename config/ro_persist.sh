#!/bin/bash
 
# stupid globals
es_version=CHANGEESVER
moloch_workdir=CHANGEDIR/moloch/bin
splunk_workdir=CHANGEDIR/splunkforwarder/bin
suricata_workdir=CHANGEDIR/suricata/bin
bro_workdir=CHANGEDIR/bro/bin
is_es_running=0
is_viewer_running=0
is_capture_running=0
is_suricata_running=0
is_bro_running=0
is_splunk_running=0
is_logstash_running=0
logagg="CHANGELOGAGG"		# Where options are splunk or logstash

#We need this otherwise cron wont respect env variables
source /etc/profile

function check_suricata {
        if [[ `service suricata status | grep running` ]]; then
          is_suricata_running=1
        else
          is_suricata_running=0
        fi
}

function check_bro {
        bro_pids=(`pidof bro`)
        if [ -z $bro_pids ]; then
                is_bro_running=0
        else
                is_bro_running=1
        fi
}

function check_splunk { 
    	SPL_PID=$(ps aux | grep splunk | grep -v grep | awk '{ print $2 }')
        if [[ -z $SPL_PID ]]; then
                is_splunk_running=0
        else
                is_splunk_running=1
        fi
}
         
function check_es {
        # Run this with ps instead of pidof cause we grep on elasticsearch and not java
        ES_PID=$(ps aux | grep elasticsearch | grep -v grep | awk '{ print $2 }')
        if [[ -z $ES_PID ]]; then
                is_es_running=0
        else
                is_es_running=1
        fi
}
 
function check_capture {
        # use pidof in () so we just get a single value
        capture_pids=(`pidof moloch-capture`)
        if [ -z $capture_pids ]; then
                is_capture_running=0
        else
                is_capture_running=1
        fi
}
 
function check_viewer {
        viewer_pid=$(ps aux | grep 'node viewer.js' | grep -v grep | awk '{ print $2 }')
        if [ -z $viewer_pid ]; then
                is_viewer_running=0
        else
                is_viewer_running=1
        fi
}

function check_logstash {
        logstash_pid=$(ps aux | grep 'logstash' | grep -v grep | awk '{ print $2 }')
        if [ -z $logstash_pid ]; then
                is_logstash_running=0
        else
                is_logstash_running=1
        fi
}
 
check_suricata
if [ $is_suricata_running -eq 0 ]; then
       echo `date`" - Restarting Suricata"
       #restart suricata
       service suricata restart
fi

check_bro
if [ $is_bro_running -eq 0 ]; then
       echo `date`" - Restarting Bro"
       #restart bro
       $bro_workdir/broctl restart
fi

if [ $logagg == "splunk" ]; then
    check_splunk
    if [ $is_splunk_running -eq 0 ]; then
           echo `date`" - Restarting Splunk"
           #restart splunk
           $splunk_workdir/splunk restart
    fi
else
    check_logstash
    if [ $is_logstash_running -eq 0 ]; then
           echo `date`" - Restarting Logstash"
           #restart logstash
           service logstash restart
    fi
fi


check_es
if [ $is_es_running -eq 0 ]; then
        echo `date`" - Starting ElasticSearch"
 
        #start es
 
        cd CHANGEDIR/moloch/elasticsearch-$es_version/
        ulimit -a
        export JAVA_HOME=/usr/bin/java
        export ES_HOSTNAME=`hostname -s`a
        ES_HEAP_SIZE=CHANGEESMEM bin/elasticsearch -d -Des.config=CHANGEDIR/moloch/etc/elasticsearch.yml
 
        #restart capture
 
        echo `date`" - Killing moloch-capture"
        moloch_pids=$(pidof moloch-capture)
        for pid in $moloch_pids; do
                echo `date`" - Killing pid $pid"
                kill -9 $pid
        done
        cd $moloch_workdir
        echo `date`" - Starting moloch-capture"
        "$moloch_workdir/run_capture.sh" &
 
        #restart viewer
 
        echo `date`" - Killing viewer"
        viewer_pid=$(ps aux | grep -v grep | grep viewer.js | awk '{print $2 '})
        kill -9 $viewer_pid
        echo `date`" - Starting viewer"
        "$moloch_workdir/run_viewer.sh" &
fi
 
check_capture
if [ $is_capture_running -eq 0 ]; then
        echo `date`" - Starting capture"
        cd $moloch_workdir
        "$moloch_workdir/run_capture.sh" &
fi
 
check_viewer
if [ $is_viewer_running -eq 0 ]; then
        echo `date`" - Starting viewer"
        cd $moloch_workdir
        "$moloch_workdir/run_viewer.sh" &
fi
