## 0.1.0
  - Plugin created with the logstash plugin generator
## 0.2.0
  - Rename of some config fields
## 0.2.1
  - Changed library for ldap queries
  - Fixed bugs concerning LDAPs connections
## 0.2.2
  - Added a no_tag_on_failure option
## 0.2.3
  - avoid hash computation if the cache is not required
  - we now use [LRU Cache](https://github.com/SamSaffron/lru_redux) as default memory caching algorithm
  - memory cache is enabled by default
## 0.2.4
  - Fix non atomic cache operation when getting a cache result
  - Updated net-ldap library version
  - We can periodicly save buffer to disk