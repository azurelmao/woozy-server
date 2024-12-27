class Woozy::Whitelist
  def initialize(@path : String)
    @bad_entries = Array(String).new
    @entries = Set(String).new

    unless File.exists?(@path)
      File.write(@path, "")
    end

    File.read(@path).each_line do |line|
      username = line.strip

      unless Woozy.valid_username?(username)
        Log.error { "Invalid username in #{@path}, ignoring entry `#{line}`" }
        @bad_entries << line
        next
      end

      @entries << username
    end
  end

  def write : Nil
    contents = String.build do |string|
      @entries.each do |entry|
        string << entry
        string << '\n'
      end

      @bad_entries.each do |bad_entry|
        string << bad_entry
        string << '\n'
      end
    end

    File.write(@path, contents)
  end

  forward_missing_to @entries
end
