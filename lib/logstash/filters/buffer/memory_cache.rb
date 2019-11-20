# encoding: utf-8
require_relative "cache_dao"

require "lru_redux"

class MemoryCache < CacheDAO

  public
  def initialize(cache_duration, cache_size)
    @cache = LruRedux::TTL::ThreadSafeCache.new(cache_size, cache_duration)
  end

  public
  def cached?(identifier)
    return @cache.key?(identifier)
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

end
