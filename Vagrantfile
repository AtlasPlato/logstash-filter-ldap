# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "ubuntu/xenial64"

  config.vm.define "logstash-filter-ldap" do |machine|
    machine.vm.hostname = "logstash-filter-ldap"
    machine.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = "2"
    end
  end

  config.vm.provision "ansible_local" do |ansible|
    ansible.provisioning_path = "/vagrant/provisioning"
    ansible.playbook = "playbook.yml"
    ansible.groups = {
      "dev-logstash" => ["logstash-filter-ldap"]
    }
    ansible.extra_vars = {
      logstash_version: "5.6.4",
      jruby_version: "jruby-1.7.27"
    }
  end

end
