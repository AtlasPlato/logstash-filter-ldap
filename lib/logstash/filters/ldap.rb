# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::Ldap < LogStash::Filters::Base

  config_name "ldap"

   config :uidNumber, :validate => :string, :required => true

   config :host, :validate => :string, :required => true

   config :ldap_port, :validate => :number, :required => false, :default => 389
   config :ldaps_port, :validate => :number, :required => false, :default => 636

   config :use_ssl, :validate => :boolean, :required => false, :default => false

   config :username, :validate => :string, :required => false

   config :password, :validate => :string, :required => false

   config :userdn, :validate => :string, :required => true
   config :userattrs, :validate => :array, :required => false,  :default => ['uid', 'gidNumber', 'givenName', 'sn']

   config :useCache, :validate => :boolean, :required => false, :default => true

   config :cache_interval, :validate => :number, :required => false, :default => 300


   public
   def register
     require 'ldap'
     @cache = {}
     @DEFAULT = "Unknown"
     @SUCCESS = "LDAP_OK"
     @FAILURE = "LDAP_ERR"
     @UNKNOWN = "LDAP_UNK"
   end

   public
   def filter(event)

     uid2resolve = event.sprintf(@uidNumber)

     exitstatus = @SUCCESS

     cached = false
     if @useCache
         cached = cached?(uid2resolve)
     end

     if cached
         login, user = cached
     else
         @logger.info("prompt LDAP for #{uid2resolve} informations")
         if use_ssl
             conn = LDAP::SSLConn.new(host=@host, port=@ldaps_port)
         else
             conn = LDAP::Conn.new(host=@host, port=@ldap_port)
         end

         res = ldapsearch(conn, uid2resolve)
         user = res['user']
         login = res['login']
         exitstatus = res['status']
         errmsg = res['err']

         cacheUID(uid2resolve, login, user)
     end

     event.set("user", user)
     event.set("login", login)

     if exitstatus != @SUCCESS
       if event.get("tags")
           event.set("tags", event.get("tags") << exitstatus)
       else
           event.set("tags", [exitstatus])
       end
     end

     filter_matched(event)
   end


   private


   def cached?(uidNumber)
     cached = @cache.fetch(uidNumber, false)
     if cached and Time.now - cached[2] <= @cache_interval
         return cached[0], cached[1]
     end
     return false
   end

   def cacheUID(uidNumber, login, user)
     @cache[uidNumber] = [login, user, Time.now]
   end

   def ldapsearch(conn, uidNumber)
     ret = { 'login' => @DEFAULT, 'user'  => @DEFAULT, 'status' => @SUCCESS, 'err' => "" }
     gid = 0

     begin
         conn.bind(username, password)
     rescue LDAP::Error => err
         @logger.error("Error: #{err.message}")
         ret['err'] = err
         ret['status']  = @FAILURE
         return ret
     end

     scope = LDAP::LDAP_SCOPE_SUBTREE

     begin
         conn.search(@userdn, scope, "(& (objectclass=posixAccount) (uid=#{uidNumber}))", @userattrs) { |entry|

             hashEntry = {}
             for k in entry.get_attributes
                 hashEntry[k] = entry.vals(k).join(" ")
             end

             ret['user']  = "#{hashEntry.fetch("givenName", "")} #{hashEntry.fetch("sn", @DEFAULT)}".strip
             ret['login'] = "#{hashEntry.fetch("uid")}"

             gid = hashEntry.fetch("gidNumber", 0)
             match = 1
         }
     rescue LDAP::Error => err
         @logger.error("Error: #{err.message}")
         ret['err'] = err
         ret['status']  = @FAILURE
         return ret
     end

     if ret['user'] == @DEFAULT
         ret['status'] = "#{@UNKNOWN}_USER"
         return ret
     end

     return ret
   end

end
