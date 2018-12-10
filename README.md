# **LAB 1:** 

**Understanding Kerberos authentication:** 

![Kerberos authentication phases](2A4B5189-1078-4EB9-B964-AD103778B05D.png)
  
  **Step 1**. Prepare two hosts with Centos 7 to use as KDC server and a client.
(Can use KDC server from Openstack and on sqadron create a 3 host cluster with Hadoop Services)

  

**Step 2**. On one host install and configure KDC. (Change the realm name)

    #yum install krb5-server krb5-libs krb5-workstation
    #vi /etc/krb5.conf
    #kdb5_util create -s
    #service krb5kdc start
    #service kadmin start

**Step 3**. Create a user principal.

    #kadmin.local
    kadmin.local: listprincs
    kadmin.local: addprinc user1@<REALM>

  

**Step 4**. Review the kdc.conf file and configuration options.

    #cat /var/kerberos/krb5kdc/kdc.conf
    #cat /var/kerberos/krb5kdc/kadm5.acl


[https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/kdc_conf.html](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/kdc_conf.html)
[https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/kadm5_acl.html](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/kadm5_acl.html)

  Configure kdc.conf so that keys can be created with different encryption types (rc4-hmac) like below:

    [realms]
    [HWX.COM] = {
    master_key_type = aes256-cts
    acl_file = /var/kerberos/krb5kdc/kadm5.acl
    dict_file = /usr/share/dict/words
    admin_keytab = /var/kerberos/krb5kdc/kadm5.keytab
    supported_enctypes = aes256-cts:normal aes128-cts:normal des3-hmac-sha1:normal arcfour-hmac:normal des-hmac-sha1:normal des-cbc-md5:normal des-cbc-crc:normal
    }

  

**Step 5**. Review the kadm5.acl, refer documentation for possible acl and the format.

 [https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/kadm5_acl.html](https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/kadm5_acl.html)

 On client install the krb5 client pkgs and configured krb5.conf.

    #yum install krb5-libs krb5-workstation
(Update krb5.conf with REALM and kdc info)
    
    [realms]
    
    [HWX.COM]
    {
     admin_server = <kadmin_server_hostname>
      kdc = <kdc_server_hostname>
    }
  

 **Step 6**. Verify if you can authenticate with the userprincipal user1 created on kdc in **step 3.**

    #kinit user1

  
**Understanding kerberos authentication with packet trace.**

  

**Step 7**. Install tcpdump and wireshark on the client host.

    #yum install -y tcpdump wireshark
        
     

**Step 8**. Start tcpdump in background and collect packet trace for STAGE 1 of kerberos authentication:

    #kdestroy
    #tcpdump -i eth0 -w /var/tmp/krb_phase1.pcap port 88 &
    #kinit user1
    #fg (CTRL+C)

  
**Step 9**. Analyse the tcpdump with wireshark and see the krb5 message being exchanged between client and krb5 server.

    #tshark -r /var/tmp/krb_phase1.pcap
    1 0 172.26.75.225 -> 172.26.85.193 KRB5 231 AS-REQ
    2 0 172.26.85.193 -> 172.26.75.225 KRB5 764 AS-REP

  (For kerberos packet details)

      #tshark -r /var/tmp/krb_phase1.pcap -O kerberos

  **Step 10**. Observe same with kerberos debug enabled on client.

    #export KRB5_TRACE=/var/tmp/krb_phase1.debug.txt
    #kdestroy
    #kinit user1
    #unset KRB5_TRACE

  Examine the debug in /var/tmp/krb_phase1debug.txt

    #cat /var/tmp/krb_phase1.debug.txt

  From the above captured info, understand the first stage of kerberos authentication:

  

**Step 11**.  Enable Pre-Authentication on the principal created observe the change in the AS request/Response.

    kadmin.local: modprinc +requires_preauth user2@RAGHAV.COM
    kadmin.local:  getprinc user2
    Principal: user2@RAGHAV.COM
    Expiration date: [never]
    Last password change: Sun Dec 09 16:40:40 UTC 2018
    Password expiration date: [none]
    Maximum ticket life: 1 day 00:00:00
    Maximum renewable life: 0 days 00:00:00
    Last modified: Sun Dec 09 22:08:17 UTC 2018 (root/admin@RAGHAV.COM)
    Last successful authentication: Sun Dec 09 22:42:37 UTC 2018
    Last failed authentication: [never]
    Failed password attempts: 0
    Number of keys: 4
    Key: vno 1, aes256-cts-hmac-sha1-96, no salt
    Key: vno 1, aes128-cts-hmac-sha1-96, no salt
    Key: vno 1, des3-cbc-sha1, no salt
    Key: vno 1, arcfour-hmac, no salt
    MKey: vno 1
    Attributes: REQUIRES_PRE_AUTH
    Policy: [none]

    #tcpdump -i eth0 -w krb_phase1_2.pcap -s 0 port 88 &
    #kinit user2@RAGHAV.COM
    fg [CTRL+C]
    #tshark -r krb_phase1_2.pcap
    Running as user "root" and group "root". This could be dangerous.
    1 0 172.26.75.225 -> 172.26.85.193 KRB5 230 AS-REQ
    2 0 172.26.85.193 -> 172.26.75.225 KRB5 292 KRB Error: KRB5KDC_ERR_PREAUTH_REQUIRED
    3 1 172.26.75.225 -> 172.26.85.193 KRB5 325 AS-REQ
    4 1 172.26.85.193 -> 172.26.75.225 KRB5 762 AS-REP

  


![Kerberos pre-authentication phases](ACCB4733-017B-4B8D-B61C-385466FEDA54.jpg)


  **PHASE 2** of kerberos authentication(Requesting service principal)

  Client after AS request, we can request service principal before connecting to a kerberized service. To simulate requesting the service principal we can use the comman kvno. Below steps we create a dummy service principal get a service ticket for that principal

  

**Step 12**.  On kdc login to kadmin prompt and create a dummy service principal:
    
    #kadmin.local
    kadmin.local: addprinc dummy/<hostname>@<REALM>

  

**Step 13**.  On client make sure you have tgt and use command kvno to request the service ticket while capturing tcpdump.
    

    #klist
    #tcpdump -r eth0 -w /var/tmp/krb_phase2.pcap port 88 &
    #kvno dummy/<hostname>@<REALM>
    fg [CTRL+C]
    
    #tshark -r /var/tmp/krb_phase2.pcap
    Running as user "root" and group "root". This could be dangerous.
    1 0 172.26.75.225 -> 172.26.85.193 KRB5 993 TGS-REQ
    2 0 172.26.85.193 -> 172.26.75.225 KRB5 963 TGS-REP

  

**PHASE 3** of kerberos authentication deals with the end application where client is supposed to send the request to application with the service ticket received in PHASE 2.

  

To observer PHASE 3 of kerberos, we have to configure a kerberized application and connect to it from client.

  

**Step 14**.  Install httpd service on the third host:
    

    #yum install httpd mod_auth_kerb mod_auth_gssapi

  

**Step 15**.  Configure httpd for kerberos :
    

    #vi /etc/httpd/conf/httpd.conf

  

Append below lines to the end of httpd.conf

    LoadModule auth_kerb_module modules/mod_auth_kerb.so
    <Location /kerberostest>
    AuthType Kerberos
    AuthName "Kerberos Login"
    KrbMethodNegotiate On
    KrbMethodK5Passwd Off
    KrbAuthRealms [EXAMPLE.COM](http://example.com/)
    KrbServiceName HTTP
    Krb5KeyTab /etc/httpd/apache.httpd.keytab
    require valid-user
    </Location>

  Create the HTML page to test kerberos authentication: 

    #mkdir -p /var/www/html/kerberostest
    #vim /etc/httpd//kerberostest/auth_kerb_page.html
    <html>
    <body>
    <h1>HTTPD kerberos authentication test!!</h1>
    </body>
    </html>

  

**Step 16.**  Create the service principal HTTP/<hostname> on the kdc and create a ketab.
    

    #kadmin.local
    kadmin.local: addprinc HTTP/<hostname>
    kadmin.local: xst -k /tmp/apache.httpd.keytab -norandkey HTTP/<hostname>

(Copy the keytab /tmp/apache.httpd.keytab to the host where httpd is installed under path /etc/httpd/)

  

**Step 17.**  Restart httpd service
    

    #service httpd restart

  

**Step 18.**  Try connecting to the httpd service using curl command:(Make sure you have tgt before execute curl)
    

    #tcpdump -i eth0 -w /var/tmp/krb_phase3.pcap -s 0 port 80
    #curl —negotiate -u : http://sec-lab1.raghav.com:80/kerberostest/auth_kerb_page.html
    #tshark -r /var/tmp/krb_phase3.pcap

  Summarize the kerberos authentication flow as observed from above steps:
