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

    sample("test" => "test2" ) do
      expect(subject).to include('givenName')
      expect(subject).to include('sn')

      expect(subject).not_to include('err')
      expect(subject).not_to include('tags')

      expect(subject.get("givenName")).to eq("VALENTIN")
      expect(subject.get("sn")).to eq("BOURDIER")
    end
  end


  describe "check simple search with customs attributs" do
    let(:config) do <<-CONFIG
      filter {
        ldap {
          identifier_value => "u501565"
          host => "#{@ldap_host}"
          ldap_port => "#{@ldap_port}"
          username => "#{@ldap_username}"
          password => "#{@ldap_password}"
          userdn => "#{@ldap_userdn}"
          attributes => ["gender", "c", "dominolanguage"]
        }
      }
      CONFIG
    end

    sample("test" => "test" ) do
      expect(subject).to include('gender')
      expect(subject).to include('c')
      expect(subject).to include('dominolanguage')

      expect(subject).not_to include('givenName')
      expect(subject).not_to include('sn')
      expect(subject).not_to include('err')
      expect(subject).not_to include('tags')

      expect(subject.get("gender")).to eq("M")
      expect(subject.get("c")).to eq("FR")
      expect(subject.get("dominolanguage")).to eq("FR")
    end
  end


  describe "check bad authentification credentials" do
    let(:config) do <<-CONFIG
      filter {
        ldap {
          identifier_value => "u501565"
          host => "example.org"
          ldap_port => "#{@ldap_port}"
          username => "test"
          password => "test"
          userdn => "#{@ldap_userdn}"
        }
      }
      CONFIG
    end

    sample("test" => "test" ) do
      expect(subject).to include('err')
      expect(subject).to include('tags')

      expect(subject).not_to include('givenName')
      expect(subject).not_to include('sn')

      expect(subject.get("tags")).to eq(["LDAP_ERR_CONN"])
      expect(subject.get("err")).to eq("Can't contact LDAP server")
    end
  end

end
