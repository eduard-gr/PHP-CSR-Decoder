# Defines our Vagrant environment
#
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

	config.vm.box = "bento/debian-7"
	config.vm.box_version = "201806.08.0"

	config.vm.hostname	="php-csr-decoder-8.0"
	config.vm.define	:"php-csr-decoder-8.0"

	#config.vm.network 'private_network', ip: '192.168.55.222'
	config.vm.network 'private_network', type: 'dhcp'

	# Mount project files
	# config.vm.synced_folder './environment', '/home/vagrant/environment',
	# 	create: true,
	# 	group: 'vagrant'
	# 	#mount_options: ['dmode=775,fmode=664']

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
		vb.name		= "PHP-CSR-DECODER-8.0"
	end


end

