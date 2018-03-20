# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

require 'digest/md5'

require_relative "buffer/ram_buffer"


class LogStash::Filters::Ldap < LogStash::Filters::Base

  config_name "ldap"

  # Definition of the filter config parameters

  config :identifier_value, :validate => :string, :required => true
  config :identifier_key, :validate => :string, :required => false, :default => "uid"
  config :identifier_type, :validate => :string, :required => false, :default => "posixAccount"

  config :target, :validate => :string, :required => false, :default => "ldap"
  config :attributes, :validate => :array, :required => false, :default => ['givenName', 'sn']

  config :host, :validate => :string, :required => true
  config :ldap_port, :validate => :number, :required => false, :default => 389
  config :ldaps_port, :validate => :number, :required => false, :default => 636
  config :use_ssl, :validate => :boolean, :required => false, :default => false

  config :username, :validate => :string, :required => false
  config :password, :validate => :string, :required => false

  config :search_dn, :validate => :string, :required => true

  config :use_cache, :validate => :boolean, :required => false, :default => false
  config :cache_type, :validate => :string, :required => false, :default => "memory"
  config :cache_memory_duration, :validate => :number, :required => false, :default => 300
  config :cache_memory_size, :validate => :number, :required => false, :default => 20000


  # Equivalent to 'initialize' method

  public
  def register
    require 'ldap'

    # Setting up some flags

    @SUCCESS = "LDAP_OK"
    @FAIL_CONN = "LDAP_ERR_CONN"
    @FAIL_FETCH = "LDAP_ERR_FETCH"
    @UNKNOWN_USER = "LDAP_UNK_USER"
    @BAD_cache_type = "LDAP_BAD_BUFF"

    # We check if cache type selected is valid

    if @use_cache
      if @cache_type == "memory"
        @logger.info("Memory cache was selected")
        @Buffer = RamBuffer.new(@cache_memory_duration, @cache_memory_size)
      else
        @logger.warn("Unknown cache type: #{@cache_type}")
        @logger.warn("Cache utilisation will be disable")
        @use_cache = false
      end
    end
  end

  # This function permet to treat an event, and will be called each time
  # an event should be processing

  public
  def filter(event)

    # We get the identifier, and create hash from it

    identifier_value = event.sprintf(@identifier_value)
    identifier_hash = hashIdentifier(@host, @port, @identifier_key, identifier_value)

    # We check if it is cache

    cached = false
    if @use_cache
      cached = @Buffer.cached?(identifier_hash)
    end

    if cached
      # If cached, we get it

      res = @Buffer.get(identifier_hash)
    else
      # We create the LDAP connection

      @logger.debug("Search for LDAP '#{identifier_value}' element")
      if use_ssl
        conn = LDAP::SSLConn.new(host=@host, port=@ldaps_port)
      else
        conn = LDAP::Conn.new(host=@host, port=@ldap_port)
      end

      # Then we launch the search

      res, exitstatus = ldapsearch(conn, @identifier_type, @identifier_key, identifier_value)

      # If we use the cache, then we store result for next searchs

      if @use_cache
        @Buffer.cache(identifier_hash, res)
      end

    end

    # Then we add result fetched from the database into current evenement

    res.each{|key, value|
      targetArray = event.get(target)
      if targetArray.nil?
        targetArray = {}
      end
      targetArray[key] = value
      event.set(target, targetArray)
    }

    # If there was a problem, we set the tag associated

    if !exitstatus.nil? && exitstatus != @SUCCESS
      if event.get("tags")
        event.set("tags", event.get("tags") << exitstatus)
      else
        event.set("tags", [exitstatus])
      end
    end

    filter_matched(event)
  end

  # Permet to create an unique hash for an value, to store it into the buffer

  private
  def hashIdentifier(host, port, identifier_key, identifier_value)
    md5 = Digest::MD5.new
    md5.update(host)
    md5.update(port.to_s)
    md5.update(identifier_key)
    md5.update(identifier_value)
    return md5.hexdigest
  end

  # Search LDAP attributes of the object

  private
  def ldapsearch(conn, identifier_type, identifier_key, identifier_value)

    exitstatus = @SUCCESS
    ret = {}

    # We create the connection

    begin
      conn.bind(username, password)
    rescue LDAP::Error => err
      @logger.error("Error while setting-up connection with LDPAP server '#{@host}': #{err.message}")
      ret["error"] = err.message
      exitstatus  = @FAIL_CONN
      return ret, exitstatus
    end

    scope = LDAP::LDAP_SCOPE_SUBTREE

    # We launch the search

    begin
      conn.search(@search_dn, scope, "(& (objectclass=#{identifier_type}) (#{identifier_key}=#{identifier_value}))", @attributes) { |entry|
        hashEntry = {}
        for k in entry.get_attributes
          ret[k] = entry.vals(k).join(" ")
        end
      }
    rescue LDAP::Error => err
      @logger.error("Error while searching informations: #{err.message}")
      ret["error"] = err.message
      exitstatus  = @FAIL_FETCH
      return ret, exitstatus
    end

    # We check if at least one attributes was set from attributes list

    suceed = false

    ret.each{|key, value|
      if @attributes.include?(key)
        suceed = true
        break
      end
    }

    # If not, it's probably because we didn't found the object

    if !suceed
      @logger.debug("Unable to find informations for element '#{identifier_value}'")
      exitstatus = "#{@UNKNOWN_USER}"
      return ret, exitstatus
    end

    return ret, exitstatus
  end


end
