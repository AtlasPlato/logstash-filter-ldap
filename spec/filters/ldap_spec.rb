# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ldap"

describe LogStash::Filters::Ldap do

  before(:each) do
    @ldap_host=ENV["ldap_host"]
    @ldap_port=ENV["ldap_port"]
    @ldap_username=ENV["ldap_username"]
    @ldap_password=ENV["ldap_password"]
    @ldap_userdn=ENV["ldap_userdn"]
  end


  describe "check simple search" do
    let(:config) do <<-CONFIG
      filter {
        ldap {
          identifier_value => "u501565"
          host => "#{@ldap_host}"
          ldap_port => "#{@ldap_port}"
          username => "#{@ldap_username}"
          password => "#{@ldap_password}"
          userdn => "#{@ldap_userdn}"
        }
      }
      CONFIG
    end

    sample("test" => "test" ) do
      expect(subject).to include('givenName')
      expect(subject).to include('sn')
      expect(subject).not_to include('err')
      expect(subject).not_to include('tags')

      expect(subject.get("givenName")).to eq("VALENTIN")
      expect(subject.get("sn")).to eq("BOURDIER")
    end
  end

end
