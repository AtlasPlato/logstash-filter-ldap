# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::Ldap < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "ldap"

  # uidNumber to resolve.
   config :uidNumber, :validate => :string, :required => true

   ##--- LDAP server specific configuration
   # LDAP host name
   config :host, :validate => :string, :required => true
   # LDAP//LDAPS port
   config :ldap_port, :validate => :number, :required => false, :default => 389
   config :ldaps_port, :validate => :number, :required => false, :default => 636
   # use SSL ?
   config :use_ssl, :validate => :boolean, :required => false, :default => false
   # LDAP username used to log to LDAP server
   config :username, :validate => :string, :required => false
   # LDAP password used to log to LDAP server
   config :password, :validate => :string, :required => false
   # as LDAP tree naming convention may vary, you must specify the dn to use for OU's user
   config :userdn, :validate => :string, :required => true
   config :userattrs, :validate => :array, :required => false,  :default => ['uid', 'gidNumber', 'givenName', 'sn']

   ##--- cache settings true//false and time of cache renewal in sec
   # shall we use caching true//false
   config :useCache, :validate => :boolean, :required => false, :default => true
   # cache persistence in second.
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
     # extract uid value from event
     uid2resolve = event.sprintf(@uidNumber)

     #STDERR.puts "UID:#{uid2resolve}"
     exitstatus = @SUCCESS
     ##--- first check cache for provided uidNumber
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

         ##--- cache infos.
         cacheUID(uid2resolve, login, user)
     end

     ##--- finaly change event to embed login, user information
     event.set("user", user)
     event.set("login", login)

     ##--- add LDAPresolve exit tag, We can use this later to reparse+reindex logs if necessaryi.
     if exitstatus != @SUCCESS
       if event.get("tags")
           event.set("tags", event.get("tags") << exitstatus)
       else
           event.set("tags", [exitstatus])
       end
     end

     # filter_matched should go in the last line of our successful code
     filter_matched(event)
   end # def filter


   private

   def cached?(uidNumber)
     # checks if pgiven uidNumber appear in the cache
     # then check for time it resides on the cache.
     # if cache introdution time > cache_interval. claim that uidNumber is not cached to force
     # update by the caller .
     cached = @cache.fetch(uidNumber, false)
     if cached and Time.now - cached[2] <= @cache_interval
         return cached[0], cached[1]
     end
     return false
   end

   def cacheUID(uidNumber, login, user)
     # basic caching mechanism using a hash
     # caveats, no size control.
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

     # ok we bound, start search
     scope = LDAP::LDAP_SCOPE_SUBTREE
     ##--- search LDAP for the user name
     begin
         conn.search(@userdn, scope, "(& (objectclass=posixAccount) (uid=#{uidNumber}))", @userattrs) { |entry|

             # convert entry object to hash for easier manipulation
             hashEntry = {}
             for k in entry.get_attributes
                 hashEntry[k] = entry.vals(k).join(" ")
             end
             # generate user full name.
             # in posix account we expect at least uid, gidNumber
             # givenName and sn may be ommited so provide default value
             ret['user']  = "#{hashEntry.fetch("givenName", "")} #{hashEntry.fetch("sn", @DEFAULT)}".strip
             ret['login'] = "#{hashEntry.fetch("uid")}"

             # extract gid for further interogation
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
end # class LogStash::Filters::Ldap
