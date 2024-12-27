class Woozy::Blacklist
  enum Mode
    Username
    Address
  end

  record Entry, username : String, address : String, mode : Mode, reason : String

  def initialize(@path : String)
    @bad_entries = Array(String).new
    @entries = Set(Entry).new

    unless File.exists?(@path)
      File.write(@path, "")
    end

    File.read(@path).each_line do |line|
      data = line.strip.split(',')

      if data.size != 4
        Log.error { "Incorrect number of values in #{@path}, ignoring entry `#{line}`" }
        @bad_entries << line
        next
      end

      username, address, mode, reason = data

      username = username.strip
      unless Woozy.valid_username?(username)
        Log.error { "Invalid username in #{@path}, ignoring entry `#{line}`" }
        @bad_entries << line
        next
      end

      address = address.strip
      unless Socket::IPAddress.valid?(address)
        Log.error { "Invalid address in #{@path}, ignoring entry `#{line}`" }
        @bad_entries << line
        next
      end

      mode = mode.strip
      case mode
      when "username"
        mode = Mode::Username
      when "address"
        mode = Mode::Address
      else
        Log.error { "Invalid mode in #{@path}, ignoring entry `#{line}`" }
        @bad_entries << line
        next
      end

      reason = reason.strip

      @entries << Entry.new(username, address, mode, reason)
    end
  end

  def write : Nil
    contents = String.build do |string|
      @entries.each do |entry|
        string << entry.username
        string << ','
        string << entry.address
        string << ','
        string << entry.mode.to_s.downcase
        string << ','
        string << entry.reason
        string << '\n'
      end

      @bad_entries.each do |bad_entry|
        string << bad_entry
        string << '\n'
      end
    end

    File.write(@path, contents)
  end

  def blacklisted?(username : String)
    @entries.find do |entry|
      entry.username == username && entry.mode.username?
    end
  end

  def ip_blacklisted?(username : String) : Entry?
    @entries.find do |entry|
      entry.username == username && entry.mode.address?
    end
  end

  forward_missing_to @entries
end
