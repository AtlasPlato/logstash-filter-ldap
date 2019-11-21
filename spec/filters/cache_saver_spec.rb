# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ldap"

describe "Test cache saver" do

  before(:each) do
    @default_cache_filepath= "/tmp/test_cache"
    @default_data = {
      :a => "fds",
      :b => "aaz"
    }
  end


  it "simple cache -> uncache process" do
    cache = CacheSaver.new(@default_cache_filepath)

    succeed, error = cache.save(@default_data)
    expect(succeed).to eq(true)
    expect(error).to be_nil

    succeed, data, error = cache.load()
    expect(succeed).to eq(true)
    expect(data).to eq(@default_data)
    expect(error).to be_nil
  end

  it "shouldn't cache process without permissions" do
    cache = CacheSaver.new("/root/fds")

    succeed, error = cache.save(@default_data)
    expect(succeed).to eq(false)
    expect(error).to be_a_kind_of(String)
  end

  it "shoudln't load non existing cache" do
    cache = CacheSaver.new(@default_cache_filepath + "_nonexistent")

    succeed, data, error = cache.load()
    expect(succeed).to eq(false)
    expect(data).to be_nil
    expect(error).to eq("Cache file doesn't exists")
  end

  it "shoudln't load a bad cache format" do
    cache = CacheSaver.new("/etc/hosts")

    succeed, data, error = cache.load()
    expect(succeed).to eq(false)
    expect(data).to be_nil
    expect(error).to be_a_kind_of(String)
  end

end