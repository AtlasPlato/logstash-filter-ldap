# encoding: utf-8

require 'base64'

class CacheSaver

  public
  def initialize(filepath)
    @filepath = filepath
  end

  public
  def save(data)
    begin
      f = File.open(@filepath, "w")
      data_raw = Base64.encode64(Marshal.dump(data))
      f.write(data_raw)
      return true, nil
    rescue StandardError => e
      return false, e.message
    ensure
      f.close unless f.nil?
    end
    return true, nil
  end

  public
  def load()
    if Pathname(@filepath).exist?
      begin
        data_raw = File.read(@filepath)
        data = Marshal.load(Base64.decode64(data_raw))
        return true, data, nil
      rescue StandardError => e
        return false, nil, e.message
      end
    else
      return false, nil, "Cache file doesn't exists"
    end
    return @cache[identifier]
  end

end
