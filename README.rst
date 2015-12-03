**Please note: The 7.1 buildscript is currently considered to be in BETA. It is a work in progress. Please report any problems or issues you encounter. Thank you!**

.. role:: math(raw)
   :format: html latex
..

.. figure:: http://i.imgur.com/Oznv1ra.jpg
   :alt: REDONION SUCKA

RedOnion is meant to provide a simple foundational build script for
those wishing to deploy network security monitoring tools on RHEL/Centos
6.7.

This script will install the following tools:

PFring - Installed w/ DKMS, all tools built with pfring support. -
http://ntop.org

Bro - Protocol Detection / Scripting / Intel Matching - https://bro.org

Suricata - By default We are only using Suricata for it's signature
matching capabilities - http://suricata-ids.org/

Moloch (All I do is hoot hoot hoot) - https://github.com/aol/moloch

Elasticsearch - for Moloch Backend -
https://www.elastic.co/products/elasticsearch

Emerging Threats Pro or Community Rulesets -
http://www.emergingthreats.net/open-source/open-source-community

Oinkmaster (Yes, i'm moving to pulled pork soon) -
http://oinkmaster.sourceforge.net/

Emerging Threats Luajit Rulesets - via Github -
https://github.com/EmergingThreats/et-luajit-scripts

Splunk Universal Forwarder (If you have a Splunk backend for log
aggregation) -
https://www.splunk.com/en\_us/download/universal-forwarder.html

Logstash w/ Elasticsearch or Syslog Support for everything else -
http://logstash.net/docs/1.4.2/

You can install them all, or you can install just a few individually.

**Installation Steps:**

1. Setup and partition server. Recommend fresh updated version of RHEL/Centos 6.7
2. git clone https://github.com/hadojae/redonion
3. Modify the global variables at the top of redonion_bootstrap.sh to fit your deployment
4. Run './redonion_bootstrap.sh -ro' as root
5. Follow any prompts during the script
6. When complete if running -ro install it will ask you to start up all the things, either start them then or later by uncommenting persistence script in crontab.

Please find further documentation on the wiki: https://github.com/hadojae/redonion/wiki/Red-Onion-Installation-Guide
