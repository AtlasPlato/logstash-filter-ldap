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

  if Vagrant.has_plugin?("vagrant-proxyconf")
    config.proxy.http     = ENV["http_proxy"]
    config.proxy.https    = ENV["https_proxy"]
    config.proxy.no_proxy = ENV["no_proxy"]
    config.proxy.enabled = { docker: false }
  end

  config.vm.provision "ansible_local" do |ansible|
    ansible.provisioning_path = "/vagrant/provisioning"
    ansible.playbook = "playbook.yml"
    ansible.galaxy_role_file = "requirements.yml"
    ansible.groups = {
      "dev-logstash" => ["logstash-filter-ldap"]
    }
    ansible.extra_vars = {
      rvm1_default_ruby_version: "jruby-9.1.13.0",
      rvm1_rubies: [
        "jruby-1.7.27",
        "jruby-9.1.13.0"
      ],
      http_proxy: ENV["http_proxy"],
      https_proxy: ENV["https_proxy"],
      no_proxy: ENV["no_proxy"]
    }
  end

end
