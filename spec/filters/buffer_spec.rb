# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/ldap"

describe "Test memory buffer" do

  before(:each) do
    @cache_memory_duration = 2
    @cache_memory_size = 10
    @buffer = MemoryCache.new(@cache_memory_duration, @cache_memory_size)
    @default_hash ="abc"
    @default_hash2 ="abcde"
    @default_content = { test_value: "b", fds: "a" }
    @default_content2 = { test_value: "b", fds: "ab", cd: "/root" }
  end


  it "set data recuperation without set value" do
    # Hash shouldn't be in cache
    expect(@buffer.get(@default_hash)).to be_nil
  end


  it "simple data recuperation work" do
    # Hash shouldn't be in cache
    expect(@buffer.get(@default_hash)).to be_nil

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should be the same as the one we cached
    expect(@default_content).to eq(content)
  end


  it "test value update without cache expiration" do
    # Hash shouldn't be in cache
    expect(@buffer.get(@default_hash)).to be_nil

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should be the same as the one we cached
    expect(@default_content).to eq(content)

    # Cache the new value
    expect(@buffer.cache(@default_hash, @default_content2)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should have been updated
    expect(@default_content2).to eq(content)
  end


  it "test value update with cache expiration" do
    # Hash shouldn't be in cache
    expect(@buffer.get(@default_hash)).to be_nil

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should be the same as the one we cached
    expect(@default_content).to eq(content)

    # Wait for cache expiration
    sleep(@cache_memory_duration + 1)

    # Cache the new value
    expect(@buffer.cache(@default_hash, @default_content2)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should have been updated
    expect(@default_content2).to eq(content)
  end

  it "test cache timeout" do
    # Hash shouldn't be in cache
    expect(@buffer.get(@default_hash)).to be_nil

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Wait for cache expiration
    sleep(@cache_memory_duration + 1)

    # Hash shouldn't be in anymore
    expect(@buffer.get(@default_hash)).to be_nil
  end

  it "export to obj without data" do
    data = @buffer.to_obj()
    expect(data).to eq([])
  end
  
  it "export to obj with data" do
    @buffer.cache(@default_hash, @default_content)
    data = @buffer.to_obj()
    expect(data.length()).to be(1)

    key, value = data[0]
    expect(key).to eq(@default_hash)
    expect(value).to eq(@default_content)
  end

  it "load from object without initial data" do
    @buffer.cache(@default_hash, @default_content)
    data = @buffer.to_obj()

    @buffer2 = MemoryCache.new(@cache_memory_duration, @cache_memory_size)
    @buffer2.from_obj(data)
    data2 = @buffer2.to_obj()

    expect(data).to eq(data2)
    expect(@buffer2.get(@default_hash)).to eq(@default_content)
  end

  it "load from object with initial data" do
    @buffer.cache(@default_hash, @default_content)
    data = @buffer.to_obj()

    @buffer2 = MemoryCache.new(@cache_memory_duration, @cache_memory_size)
    @buffer2.cache(@default_hash2, @default_content2)
    @buffer2.from_obj(data)
    data2 = @buffer2.to_obj()

    expect(data).to eq(data2)
    expect(@buffer2.get(@default_hash)).to eq(@default_content)
    expect(@buffer2.get(@default_hash2)).to be_nil
  end

  it "load without anything in the cache" do
    data = @buffer.to_obj()
    
    @buffer2 = MemoryCache.new(@cache_memory_duration, @cache_memory_size)
    @buffer2.from_obj(data)
    data2 = @buffer2.to_obj()

    expect(data).to eq(data2)
    expect(data2.length()).to be(0)
  end

end
