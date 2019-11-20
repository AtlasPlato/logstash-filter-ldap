# encoding: utf-8

require_relative '../spec_helper'
require "logstash/filters/ldap"


describe "Test memory buffer" do

  before(:each) do
    @cache_memory_duration = 2
    @cache_memory_size = 10
    @buffer = MemoryCache.new(@cache_memory_duration, @cache_memory_size)
    @default_hash ="abc"
    @default_content = { test_value: "b", fds: "a" }
    @default_content2 = { test_value: "b", fds: "ab", cd: "/root" }
  end


  it "set data recuperation without set value" do
    # Hash shouldn't be in cache
    expect(@buffer.cached?(@default_hash)).to eq(false)
  end


  it "simple data recuperation work" do
    # Hash shouldn't be in cache
    expect(@buffer.cached?(@default_hash)).to eq(false)

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Hash should be in cache
    expect(@buffer.cached?(@default_hash)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should be the same as the one we cached
    expect(@default_content).to eq(content)
  end


  it "test value update without cache expiration" do
    # Hash shouldn't be in cache
    expect(@buffer.cached?(@default_hash)).to eq(false)

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Hash should be in cache
    expect(@buffer.cached?(@default_hash)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should be the same as the one we cached
    expect(@default_content).to eq(content)

    # Cache the new value
    expect(@buffer.cache(@default_hash, @default_content2)).to eq(true)

    # Hash should be in cache, with its new value
    expect(@buffer.cached?(@default_hash)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should have been updated
    expect(@default_content2).to eq(content)
  end


  it "test value update with cache expiration" do
    # Hash shouldn't be in cache
    expect(@buffer.cached?(@default_hash)).to eq(false)

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Hash should be in cache
    expect(@buffer.cached?(@default_hash)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should be the same as the one we cached
    expect(@default_content).to eq(content)

    # Wait for cache expiration
    sleep(@cache_memory_duration + 1)

    # Cache the new value
    expect(@buffer.cache(@default_hash, @default_content2)).to eq(true)

    # Hash should be in cache, with its new value
    expect(@buffer.cached?(@default_hash)).to eq(true)

    # Get the cached value
    content = @buffer.get(@default_hash)

    # Value should have been updated
    expect(@default_content2).to eq(content)
  end

  it "test cache timeout" do
    # Hash shouldn't be in cache
    expect(@buffer.cached?(@default_hash)).to eq(false)

    # Cache the value
    expect(@buffer.cache(@default_hash, @default_content)).to eq(true)

    # Wait for cache expiration
    sleep(@cache_memory_duration + 1)

    # Hash shouldn't be in anymore
    expect(@buffer.cached?(@default_hash)).to eq(false)
  end

end
