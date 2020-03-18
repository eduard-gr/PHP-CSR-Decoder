# Defines our Vagrant environment
#
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

	config.vm.box	= "ubuntu/xenial64"
	#config.vm.box_version		= "6.1.4r136177"
	#config.vm.box_check_update	= false

	config.vm.hostname	="php-csr-decoder-5.6"
        config.vm.define	:"php-csr-decoder-5.6"

	config.vm.network 'private_network', ip: '192.168.55.222'
	#config.vm.network "private_network", type: "dhcp"

	# Mount project files
	config.vm.synced_folder './environment', '/home/vagrant/environment',
		create: true,
		group: 'vagrant'
		#mount_options: ['dmode=775,fmode=664']

	# Mount project files
	config.vm.synced_folder './src', '/home/vagrant/src',
		create: true,
		group: 'vagrant'
		#mount_options: ['dmode=775,fmode=664']



	# Configure VirtualBox params
	config.vm.provider "virtualbox" do |vb|
		vb.memory   = 2048
		vb.cpus     = 2
		vb.gui		= false
		vb.name		= "PHP-CSR-DECODER-5.6"
	end

	# Provision - Install components
	config.vm.provision "Install components", type: "shell" do |sh|
		sh.path = "environment/setup.sh"
		sh.args = []
		sh.keep_color = 1
	end
end

