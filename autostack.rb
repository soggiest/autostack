####TO DO:
#ADD METHOD TO CAPTURE THE INPUT, RATHER THAN HAVE IT IN THE MODULES THEMSELVES
#ADD THE ABILITY TO RECEIVE INPUTS FROM A FILE


def find_dependencies 


end

def install(package_name) 
	install_out = `yum install -y #{package_name}`
end

def configure_firewall(fire_rule) 
	fire_out 	 = `iptables -L INPUT | grep -n REJECT`
	append_find 	 = /(\w*):/.match fire_out
	append_num 	 = append_find[1]
	append_num 	 = append_num.to_i - 2
	
#	puts "Iptables Command:iptables -I INPUT #{append_num} #{fire_rule}" 

	append_out 	 = `iptables -I INPUT #{append_num} #{fire_rule}`
	save_out         = `service iptables save`
	service_restart  = `service iptables restart`
end

############Install Database Server	

def configure_db 
	puts "Installing MYSQL database\n----\n"

	package_name = "mysql-server"
	install(package_name)

	puts "Configuring Firewall for MYSQL\n----\n"

	fire_rule = "-p tcp -m multiport --dports 3306 -j ACCEPT"
	configure_firewall(fire_rule)

	puts "Configuring MYSQL\n----\n"

	puts "Enter Database Password:"

	db_pass = gets
	db_pass = db_pass.chomp

	service_start   = `service mysqld start`
	chkconfig_start = `chkconfig mysqld on`
	db_out 		= `/usr/bin/mysqladmin -u root password #{db_pass}`
	return db_pass
end


############Install Message Broker

def configure_message_broker 
	puts "Installing Message Broker\n----\n"

	package_name = "qpidd-cpp-server qpid-cpp-server-ssl"
	install(package_name)

	puts "How will clients connect to the Message Broker:(anonymous, plain, or md5)"
	message_sec = gets
	message_sec = message_sec.chomp

	qpidd_conf = File.open("/etc/sasl2/qpidd.conf")

	if message_sec == "anonymous"
		#don't do anything
	elsif message_sec == "plain"
		install("cyrus-sasl-plain")
		qpidd_conf.gsub(/mech_list:.*$/, /mech_list: PLAIN/) 

	elsif message_sec == "md5"
		install("cyrus-sasl-md5")
		qpidd_conf.gsub(/mech_list:.*$/, /mech_list: DIGEST-MD5/)

		#add some stuff to add users
	else 
		err = "Couldn't determine security method"
	end

	puts "Configuring Firewall for Message Broker\n----\n"

	fire_rule = "-p tcp -m tcp --dport 5672 -j ACCEPT"

	configure_firewall(fire_rule)

	qpidd_out = `service qpidd start`
	chkconfig = `chkconfig qpidd on`

	configure_sasl
	configure_tls_ssl

	qpidd_start     = `service qpidd start`
	qpidd_chlconfig = `chkconfig qpidd on`
end

def configure_sasl 
	user_question = "no"

	puts "Do you want to specify a user to the SASL Database?(yes/no)"
	user_question = gets 
	user_question = user_question.chomp

	if user_question == "yes"
		begin
			puts "Enter username (username@domain):"
			username = gets
			username = username.chomp
			sasl_add = `saslpasswd2 -f /var/lib/qpidd/qpidd.sasldb -u QPID #{username}`
			puts "Do you want to add another user?(yes/no)"
			another_user = gets
			another_user = another_user.chomp
			retry if another_user == "yes"
		end
	end

	puts "Configuring SASL guest account\n----\n"
	sasl_guest  = `echo guest | saslpasswd2 -f /var/lib/qpidd.sasldb -u QPID guest`

	puts "Configuring SASL Cinder\n----\n"
	sasl_cinder  = `echo cinder | saslpasswd2 -f /var/lib/qpidd/qpidd.sasldb -u QPID cinder`
	
	puts "Configuring SASL Neutron\n----\n"
	sasl_neutron = `echo neutron | saslpasswd2 -f /var/lib/qpidd/qpidd.sasldb -u QPID neutron`
	
	puts "Configuring SASL Nova\n----\n"
	sasl_nova    = `echo nova | saslpasswd2 -f /var/lib/qpidd/qpidd.sasldb -u QPID nova`
end

def configure_tls_ssl 
	puts "Enter SSL password:"
	ssl_password = gets
	ssl_password = ssl_password.chomp

	cert_dir     = "/tmp/openstack_certs"
	cert_pw_file = "/tmp/openstack_certs/pw_file"

	puts "Creating SSL password dir\n----\n"
	cert_dir_creation = `mkdir #{cert_dir}`
	
	puts "Creating SSL password file\n----\n"

	pw_file_create    = `echo #{ssl_password} > #{cert_pw_file}` 

	puts "Creating Certificates\n----\n"
	cert_create       = `certutil -N -d #{cert_dir} -f #{cert_pw_file}`
	
	puts "Creating Certificate nickname\n----\n"
	cert_set_nick     = `certutil -S -d #{cert_dir} -n openstack -s "CN=openstack" -t "CT,," -x -f #{cert_pw_file} -z /usr/bin/certutil`
	
	puts "Exporting PK12 certs\n----\n"
	export_pk12       = `pk12util -o #{cert_dir}/p12_export -n openstack -d #{cert_dir} -w #{cert_pw_file}`
	
	puts "Exporting SSL certs\n----\n"
	export_ssl	  = `openssl pkcs12 -in #{cert_dir}/p12_export -out #{cert_dir}/openstack_cert -nodes -clcerts -passin  pass:#{ssl_password}`

end
############Install Identity Service


def configure_identity_db(db_passwd) 
	puts "Installing Openstack Identity Services"
	package_name = "openstack-keystone openstack-utils openstack-selinux"
	install(package_name)

	puts "Enter password for Keystone Database"
	keystone_pw = gets
	keystone_pw =keystone_pw.chomp
	
	puts "Configuring Openstack Identity Database script\n----\n"

	mysql_script = "CREATE DATABASE keystone;\n USE keystone;\n GRANT ALL ON keystone.* TO 'keystone'@'%' IDENTIFIED BY \'#{db_passwd}\';\n GRANT ALL ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY \'#{keystone_pw}\';\n FLUSH PRIVILEGES;\n quit"
	File.open("/tmp/mysqlscript", 'w') { | file| file.write mysql_script}
	
	puts "Configuring Openstack Identity Database\n----\n"
	mysql_create = `mysql -u root -p#{db_passwd} < /tmp/mysqlscript`

	puts "Removing Database Configuration Script\n----\n"
	remove_mysql = `rm /tmp/mysqlscript`

	return keystone_pw
end

def configure_identity_service(keystone_passwd) 
	puts "Creating Admin Token\n----\n"

	#create_token = `export SERVICE_TOKEN=$(openssl rand -hex 10)`

	service_token = `openssl rand -hex 10`
	service_token = service_token.chomp
	ks_file       = "/root/ks_admin_token"
	puts "#{service_token}"
	#echo_token   = `echo #{service_token} > #{ks_file}`
	File.open(ks_file, 'w') { |file| file.write service_token}

	puts "Setting Admin Token\n----\n"
	stack_config = `openstack-config --set /etc/keystone/keystone.conf DEFAULT admin_token #{service_token}`
	
	puts "Setting the Database Connection string\n----\n"
	stack_db        = `openstack-config --set /etc/keystone/keystone.conf sql connection mysql://keystone:#{keystone_passwd}@127.0.0.1/keystone`

	puts "Configuring PKI\n----\n"
	keystone_create = `keystone-manage pki_setup --keystone-user keystone --keystone-group keystone`
	chown_keystone  = `chown -R keystone:keystone /var/log/keystone /etc/keystone/ssl/`

	puts "Enabling Identity Service to use PKI files\n----\n"
	token_signing = `openstack-config --set /etc/keystone/keystone.conf signing token_format PKI`
	certfile_sign = `openstack-config --set /etc/keystone/keystone.conf signing certfile /etc/keystore/ssl/certs/signing_cert.pem`
	keyfile_sign  = `openstack-config --set /etc/keystone/keystone.conf signing keyfile /etc/keystone/ssl/private/signing_key.pem`
	ca_certs_sign = `openstack-config --set /etc/keystone/keystone.conf signing ca_certs /etc/keystone/ssl/certs/ca.pem`
	key_size_sign = `openstack-config --set /etc/keystone/keystone.conf signing key_size 1024`
	validday_sign = `openstack-config --set /etc/keystone/keystone.conf signing valid_days 3650`
	ca_pass_sign  = `openstack-config --set /etc/keystone/keystone.conf signing ca_password None`

	###At this point I'm electing to not do the LDAP set up, maybe after I get the rest running

	puts "Configuring firewall for Identity Service\n----\n"
	fire_rule = "-p tcp -m multiport --dports 5000,35357 -j ACCEPT"
	configure_firewall(fire_rule)

	puts "Populating Identity Service database\n----\n"
	pop_keystone = `su keystone -s /bin/sh -c "keystone-manage db_sync"`

	puts "Starting Identity Service\n----\n"
	identity_start = `service openstack-keystone start`
	chkconfig_is   = `chkconfig openstack-keystone on`	

	return service_token
end

def create_identity_endpoint(ip_address, service_token)
	puts "Exporting Service Token\n----\n"
	#service_token      = `export SERVICE_TOKEN=\`cat ~/ks_admin_token\``
	service_endpoint   = "http://#{ip_address}:35357/v2.0"
	#endpoint_create    = `export SERVICE_ENDPOINT=\"#{service_endpoint}\"`

	puts "Creating Keystone Service: Keystone\n----\n"

	puts" keystone command: keystone --os-token #{service_token} --os-endpoint #{service_endpoint} service-create --name=keystone --type=identity --description=\"Keystone Identity Service\"" 

	service_create  = `keystone --os-token #{service_token} --os-endpoint #{service_endpoint} service-create --name=keystone --type=identity --description=\"Keystone Identity Service\"` 
	
	puts "Service Create: #{service_create}"
	
	service_id		= /id.*\|(\w.*)|/.match service_create
	service_id		= service_id[1]

	puts "Service ID: #{service_id}"

	endpoint_create = `keystone endpoint-create --service_id #{service_id} --publicurl 'http://#{ip_address}:5000/v2.0' --adminurl 'http://#{ip_address}:35357/v2.0' --internalurl 'http://#{ip_address}/v2.0'`

	#####There's a possibility to create identity endpoint in different regions. Maybe add that shiz

	abort("----------------\nGetting Identity Endpoints to work\n--------------\n")
	
end

def create_admin_account(admin_passwd, ip_address)
	puts "Creating admin account"

	
	service_endpoint   = `export SERVICE_ENDPOINT=\"http://#{ip_address}:35357/v2.0\"`

	admin_create = `keystone user-create --name admin --pass #{admin_passwd}`
	admin_id	 = /id.*|(\w*)|/.match admin_create
	admin_id	 = admin_id[1]

	role_create  = `keystone role-create --name admin`
	role_id		 = /id.*|(\w*)|/.match role_create
	role_id		 = role_id[1]

	tenant_create = `keystone tenant-create --name admin`
	tenant_id	  = /id.*|(\w*)|/.match tenant_create
	tenant_id	  = tenant_id[1]

	user_create	  = `keystone user-role-add --user-id #{admin_id} --role-id #{role_id} --tenant-id #{tenant_id}`

	os_username	   = `export OS_USERNAME=admin`
	os_tenant_name = `export OS_TENANT_NAME=admin`
	os_password    = `export OS_PASSWORD=#{admin_passwd}`
	os_auth_url    = `export OS_AUTH_URL=http://#{ip_address}:35357/v2.0/`
	ps1_export	   = `export PS1='[\u@\h \W(keystone_admin)]\\$ '`

	return admin_id
end

def create_user_account(user_account, user_passwd, ip_address)
	puts "Create User Account:#{user_account}"

	source_admin = `source ~/keystonerc_admin`

	user_create = `keystone user-create --name #{user_account} --pass #{user_passwd}`
	user_id	 = /id.*|(\w*)|/.match user_create
	user_id	 = user_id[1]

	role_create  = `keystone role-create --name Member`
	role_id		 = /id.*|(\w*)|/.match role_create
	role_id		 = role_id[1]

	tenant_create = `keystone tenant-create --name #{user_account}`
	tenant_id	  = /id.*|(\w*)|/.match tenant_create
	tenant_id	  = tenant_id[1]

	user_create	  = `keystone user-role-add --user-id #{user_id} --role-id #{role_id} --tenant-id #{tenant_id}`

	os_username	   = `export OS_USERNAME=#{user_account}`
	os_tenant_name = `export OS_TENANT_NAME=#{user_account}`
	os_password    = `export OS_PASSWORD=#{user_passwd}`
	os_auth_url    = `export OS_AUTH_URL=http://#{ip_address}:5000/v2.0/`
	ps1_export	   = `export PS1='[\u@\h \W(keystone_#{user_account})]\\$ '`

	return user_id
end

def create_services_tenant
	puts "Creating Services Tenant"

	source_admin = `source ~/keystonerc_admin`

	services_tenant = `keystone tenant-create --name services --description "Services Tenant"`
end

def validate_identity_installation(admin_id, user_id)
	source_admin = `source ~/keystonerc_admin`
	user_list = `keystone user-list`
	if (user_list.include? admin_id) && (user_liast.include? user_id)
		puts "Admin account verified"
	else
		kill "Admin account failed due to: #{user_list}"
	end

	source_user = `source ~/keystonerc_user`
	user_list = `keystone user-list`
	if (user_list.include? "HTTP 303")
		puts "Normal user access verified"
	else
		kill "Normal access verification failed due to: #{user_list}"
	end	

	token_get = `keystone token-get`
	if (token_get.include? userid)
		puts "Normal user token received"
	else
		kill "Token get failed, you suck"
	end

end

############Install Object Storage Service

def configure_object_storage
############THIS IS WHERE I STOPPED, GOTTA FIGURE OUT HOW TO AUTOMATE MAKING AN EXT4 PARTITION, MAYBE IT JUST HAS TO BE PART OF THE TEMPLATE?



end

def validate_object_storage_service

end

############Installing OPenStack Image Service

def create_image_database

end

def configure_image_service 

end

def start_api 

end

def validate_image_installation 

end

############Installing Block Storage

def block_storage_prereq_config 

end

def common_block_storage_config 

end

def volume_block_storage_config 

end

def start_storage_services 

end

def validate_storage_installation 

end

#############Installing Networking Service

def networking_prereq_configuration 

end

def common_networking_configuration 

end

def config_network_service 

end

def config_dhcp_agent 

end

def config_provider_network 

end

def config_plug_in_agent 

end

def config_l3_agent 

end

def validate_networking_installation 

end

################Installing Openstack Compute Service

def compute_service_requirements 

end

admin_passwd = 'admin'

configure_db

db_passwd = configure_message_broker

#db_passwd = "admin"
keystone_pw = configure_identity_db(db_passwd)

service_token = configure_identity_service(keystone_pw)

###GATHER THE IDENTITY SERVER'S IP ADDRESS
#ip_address = `ifconfig #{dev_name}`
#ip_address = /inet\s(\w.*)\snet/
#ip_address = ip_address[1]

puts "What is the IP address for the Identity Service?:"
ip_address = gets
ip_address = ip_address.chomp

create_identity_endpoint(ip_address, service_token)
admin_id = create_admin_account(admin_passwd)

user_account = "nlane"
user_passwd  = "nlane" 
user_id = create_user_account(user_account, user_passwd, ip_address)

create_services_tenant

####Theres a way to configure the Identity Service to use External Authentication

validate_identity_installation(admin_id, user_id)
