# ldap_auth_server
LDAP authenticate server

During some investigations of binding users to special software installation, often
LDAP access is mostly implemented. However, in most cases you have no full LDAP 
service implemented. The idea of this project is to have something which acts like 
an LDAP server and is doing the authentication via an external provider, e.g. SASL 
for krb5 or pam. 
