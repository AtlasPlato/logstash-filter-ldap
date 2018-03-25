# encoding: utf-8

require_relative '../spec_helper'
require "logstash/filters/ldap"


describe "Test memory buffer" do

  before(:each) do
    @cache_memory_duration = 2
    @cache_memory_size = 10
    @buffer = RamBuffer.new(@cache_memory_duration, @cache_memory_size)
    @default_hash ="abc"
    @default_content = {test_value: "b", fds: "a"}
  end

  it "set data recuperation without set value" do
    expect(@buffer.cached?(@default_hash)).to eq(false)
  end

  it "simple data recuperation work" do
    expect(@buffer.cached?(@default_hash)).to eq(false)

    @buffer.cache(@default_hash, @default_content)

    expect(@buffer.cached?(@default_hash)).to eq(true)

    content = @buffer.get(@default_hash)

    expect(@default_content).to eq(content)
  end

  it "check buffer limit" do
    (1..@cache_memory_size).each do |n|
      @buffer.cache(n.to_s, @default_content)
      expect(@buffer.cached?(n.to_s)).to eq(true)
      content = @buffer.get(n.to_s)
      expect(@default_content).to eq(content)
    end
    @buffer.cache((@cache_memory_size + 1).to_s, @default_content)
    expect(@buffer.cached?((@cache_memory_size + 1).to_s)).to eq(false)
  end

  it "test buffer timeout" do
    expect(@buffer.cached?(@default_hash)).to eq(false)

    @buffer.cache(@default_hash, @default_content)

    sleep(@cache_memory_duration + 1)

    expect(@buffer.cached?(@default_hash)).to eq(false)
  end

end
