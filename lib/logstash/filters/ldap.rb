# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require 'digest/md5'


class BufferDAO

  public
  def cached?(identifier)
    raise('Not implemented')
  end

  public
  def cache(identifier, hash)
    raise('Not implemented')
  end

  public
  def get(identifier)
    raise('Not implemented')
  end

end


class RamBuffer < BufferDAO

  public
  def initialize(cache_interval)
    @cache_interval = cache_interval
    @cache = {}
  end

  public
  def cached?(identifier)
    cached = @cache.fetch(identifier, false)
    if cached and Time.now - cached[0] <= @cache_interval
      return true
    end
    return false
  end

  public
  def cache(identifier, hash)
    @cache[identifier] = [Time.now, hash]
  end

  public
  def get(identifier)
    cache_tuple = @cache.fetch(identifier)
    return cache_tuple[1]
  end

end


class LogStash::Filters::Ldap < LogStash::Filters::Base

  config_name "ldap"

  config :identifier_value, :validate => :string, :required => true
  config :identifier_key, :validate => :string, :required => false, :default => "uid"
  config :identifier_type, :validate => :string, :required => false, :default => "posixAccount"

  config :attributs, :validate => :array, :required => false, :default => ['givenName', 'sn']

  config :host, :validate => :string, :required => true
  config :ldap_port, :validate => :number, :required => false, :default => 389
  config :ldaps_port, :validate => :number, :required => false, :default => 636
  config :use_ssl, :validate => :boolean, :required => false, :default => false

  config :username, :validate => :string, :required => false
  config :password, :validate => :string, :required => false

  config :userdn, :validate => :string, :required => true

  config :use_cache, :validate => :boolean, :required => false, :default => true
  config :cache_interval, :validate => :number, :required => false, :default => 300


  public
  def register
    require 'ldap'

    @Buffer = RamBuffer.new(@cache_interval)

    @SUCCESS = "LDAP_OK"
    @FAIL_CONN = "LDAP_ERR_CONN"
    @FAIL_FETCH = "LDAP_ERR_FETCH"
    @UNKNOWN_USER = "LDAP_UNK_USER"
  end

  public
  def filter(event)

    identifier_hash = hashIdentifier(@host, @port, @identifier_key, @identifier_value)

    cached = false
    if @use_cache
      cached = @Buffer.cached?(identifier_hash)
    end

    if cached
      res = @Buffer.get(identifier_hash)
    else
      @logger.info("prompt LDAP for #{identifier_hash} informations")
      if use_ssl
        conn = LDAP::SSLConn.new(host=@host, port=@ldaps_port)
      else
        conn = LDAP::Conn.new(host=@host, port=@ldap_port)
      end

      res, exitstatus = ldapsearch(conn, @identifier_type, @identifier_key, @identifier_value)

      @Buffer.cache(identifier_hash, res)
    end

    res.each{|key, value|
      event.set(key, value)
    }

    if !exitstatus.nil? && exitstatus != @SUCCESS
      if event.get("tags")
        event.set("tags", event.get("tags") << exitstatus)
      else
        event.set("tags", [exitstatus])
      end
    end

    filter_matched(event)
  end

  private
  def hashIdentifier(host, port, identifier_key, identifier_value)
    md5 = Digest::MD5.new
    md5.update(host)
    md5.update(port.to_s)
    md5.update(identifier_key)
    md5.update(identifier_value)
    return md5.hexdigest
  end

  private
  def ldapsearch(conn, identifier_type, identifier_key, identifier_value)

    exitstatus = @SUCCESS
    ret = {}

    begin
      conn.bind(username, password)
    rescue LDAP::Error => err
      @logger.error("Error: #{err.message}")
      ret['err'] = err.message
      exitstatus  = @FAIL_CONN
      return ret, exitstatus
    end

    scope = LDAP::LDAP_SCOPE_SUBTREE

    begin
      conn.search(@userdn, scope, "(& (objectclass=#{identifier_type}) (#{identifier_key}=#{identifier_value}))", @attributs) { |entry|
        hashEntry = {}
        for k in entry.get_attributes
          ret[k] = entry.vals(k).join(" ")
        end
      }
    rescue LDAP::Error => err
      @logger.error("Error: #{err.message}")
      ret['err'] = err.message
      exitstatus  = @FAIL_FETCH
      return ret, exitstatus
    end

    suceed = false

    ret.each{|key, value|
      if @attributs.include?(key)
        suceed = true
        break
      end
    }

    if !suceed
      exitstatus = "#{@UNKNOWN_USER}"
      return ret, exitstatus
    end

    return ret, exitstatus
  end


end
