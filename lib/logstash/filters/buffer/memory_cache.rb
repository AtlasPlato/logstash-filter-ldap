# encoding: utf-8
require_relative "cache_dao"

require "lru_redux"

class MemoryCache < CacheDAO

  public
  def initialize(cache_duration, cache_size)
    @cache = LruRedux::TTL::ThreadSafeCache.new(cache_size, cache_duration)
  end

  public
  def cache(identifier, hash)
    @cache[identifier] = hash
    return true
  end

  public
  def get(identifier)
    return @cache[identifier]
  end

  public
  def to_obj()
    return @cache.to_a
  end

  public
  def from_obj(obj)
    @cache.clear
    obj.each {|key, value|
      @cache[key] = value
    }
  end

end
