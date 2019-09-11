/var/log/ldap_auth.log
{
	rotate 7
	weekly
	missingok
	notifempty
	delaycompress
	compress
        copytruncate
}

