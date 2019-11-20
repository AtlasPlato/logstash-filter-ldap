# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

require 'digest/md5'

require_relative "buffer/memory_cache"


class LogStash::Filters::Ldap < LogStash::Filters::Base

  config_name "ldap"

  # Definition of the filter config parameters

  config :identifier_value, :validate => :string, :required => true
  config :identifier_key, :validate => :string, :required => false, :default => "uid"
  config :identifier_type, :validate => :string, :required => false, :default => "posixAccount"

  config :target, :validate => :string, :required => false, :default => "ldap"
  config :attributes, :validate => :array, :required => false, :default => []

  config :host, :validate => :string, :required => true
  config :ldap_port, :validate => :number, :required => false, :default => 389
  config :ldaps_port, :validate => :number, :required => false, :default => 636
  config :use_ssl, :validate => :boolean, :required => false, :default => false

  config :username, :validate => :string, :required => false
  config :password, :validate => :password, :required => false

  config :search_dn, :validate => :string, :required => true

  config :use_cache, :validate => :boolean, :required => false, :default => false
  config :cache_type, :validate => :string, :required => false, :default => "memory"
  config :cache_memory_duration, :validate => :number, :required => false, :default => 300
  config :cache_memory_size, :validate => :number, :required => false, :default => 20000

  config :enable_error_logging, :validate => :boolean, :required => false, :default => false
  config :no_tag_on_failure, :validate => :boolean, :required => false, :default => false


  # Equivalent to 'initialize' method

  public
  def register
    require 'net/ldap'

    # Setup some flags

    @SUCCESS = "LDAP_OK"
    @FAIL_PROCESSING = "LDAP_ERROR"
    @NOT_FOUND = "LDAP_NOT_FOUND"

    # Setup some variables

    @attributes_uppercase = @attributes.map(&:upcase)

    @search_all_attributes = (@attributes.length == 0)

    # We check if cache type selected is valid

    if @use_cache
      if @cache_type == "memory"
        @logger.info("Memory cache was selected")
        @Buffer = MemoryCache.new(@cache_memory_duration, @cache_memory_size)
      else
        @logger.warn("Unknown cache type: #{@cache_type}")
        @logger.warn("Cache utilisation will be disable")
        @use_cache = false
      end
    end

    # We setup our ldap connection

    if @use_ssl
      @ldap = Net::LDAP.new :host => @host,
      :port => @ldaps_port,
      :auth => {
        :method => :simple,
        :username => @username,
        :password => @password.value
      },
      :encryption => {
        :method => :simple_tls
      }
    else
      @ldap = Net::LDAP.new :host => @host,
      :port => @ldap_port,
      :auth => {
        :method => :simple,
        :username => @username,
        :password => @password.value
      }
    end

    # We check the state of the connection

    begin
      if !@ldap.bind()
        raise(@ldap.get_operation_result.error_message)
      end
    rescue Exception => err
      @logger.error("Error while setting-up connection with LDAP server '#{@host}': #{err.message}")
    end
  end

  # This function will be called each time an event should be processed

  public
  def filter(event)

    # We get the identifier, and create hash from it

    identifier_value = event.sprintf(@identifier_value)
    identifier_hash = hashIdentifier(@host, @port, @identifier_key, identifier_value)

    # We check if the cache is required

    cached = false
    if @use_cache
      cached = @Buffer.cached?(identifier_hash)
    end

    if cached
      # If cached, we get it

      res = @Buffer.get(identifier_hash)
    else
      # We create the LDAP connection

      @logger.debug? && @logger.debug("Search for LDAP '#{identifier_value}' element")

      # Then we launch the search

      res, exitstatus = ldapsearch(identifier_value)

      # If we use the cache, then we store the result for futher use

      if @use_cache
        @Buffer.cache(identifier_hash, res)
      end

    end

    # Then we add result fetched from the database into current event

    res.each{|key, value|
      targetArray = event.get(@target)
      if targetArray.nil?
        targetArray = {}
      end
      targetArray[key] = value
      event.set(@target, targetArray)
    }

    # If there is a problem, we set the tag associated

    if !no_tag_on_failure && !exitstatus.nil? && exitstatus != @SUCCESS
      if event.get("tags")
        event.set("tags", event.get("tags") << exitstatus)
      else
        event.set("tags", [exitstatus])
      end
    end

    filter_matched(event)
  end

  # Create an unique hash for an event

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
  def ldapsearch(identifier_value)

    exitstatus = @SUCCESS
    ret = {}

    # We create the request parameters

    object_type_filter = Net::LDAP::Filter.eq("objectclass", @identifier_type)
    identifier_filter = Net::LDAP::Filter.eq(@identifier_key, "#{identifier_value}")

    full_filter = Net::LDAP::Filter.join(identifier_filter, object_type_filter)
    treebase = @search_dn

    # We launch the request

    suceed = false

    begin

      @ldap.search( :base => treebase, :filter => full_filter, :attributes => @attributes) do |entry|
        entry.each do |attribute, values|
          suceed = true
          if @attributes_uppercase.include?(attribute.upcase.to_s) or @search_all_attributes
            ret[attribute] = values.join(" ")
          end
        end
      end

      if !@ldap.get_operation_result.error_message.empty?
        raise(@ldap.get_operation_result.error_message)
      end

    rescue Exception => err
      @logger.error("Error while searching informations: #{err.message}")
      @enable_error_logging && ret["error"] = err.message
      exitstatus  = @FAIL_PROCESSING
      return ret, exitstatus
    end

    # If not, it's probably because we didn't found the object

    if !suceed
      @logger.debug? && @logger.debug("Unable to find informations for element '#{identifier_value}'")
      exitstatus = @NOT_FOUND
      return ret, exitstatus
    end

    return ret, exitstatus
  end

end
