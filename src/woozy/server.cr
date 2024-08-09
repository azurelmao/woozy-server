require "sqlite3"
require "crypto/bcrypt/password"
require "woozy"
require "./world/world"

class Woozy::FreshClient
  property connection : TCPSocket
  property auth_channel = Channel(Client?).new

  def initialize(@connection)
  end
end

class Woozy::Client
  property connection : TCPSocket
  property packet_channel = Channel(Packet).new
  property username : String

  def initialize(@connection, @username)
  end
end

class Woozy::Server
  Username = "[Server]"

  enum BlacklistMode
    Username
    Address
  end

  record BlacklistEntry, username : String, address : String, mode : BlacklistMode, reason : String

  def initialize(host : String, port : Int32)
    @server = TCPServer.new(host, port)
    @client_channel = Channel(FreshClient).new
    @fresh_clients = Array(FreshClient).new
    @clients = Array(Client).new

    unless File.exists?("openssl.cfg")
      File.write("openssl.cfg", <<-CFG)
        [req]
        distinguished_name = req_distinguished_name
        req_extensions = v3_req
        prompt = no

        [req_distinguished_name]
        organizationName = woozy-server
        organizationalUnitName = azurelmao
        commonName = localhost

        [ v3_req ]
        basicConstraints = CA:FALSE
        keyUsage = nonRepudiation, digitalSignature, keyEncipherment
        subjectAltName = @alt_names

        [alt_names]
        DNS.1 = *.localhost
      CFG
    end

    unless File.exists?("private.key")
      `openssl genpkey -algorithm ED25519 > private.key`
    end

    unless File.exists?("public.cert")
      `openssl req -new -key private.key -config openssl.cfg -out unsigned.csr`
      `openssl x509 -req -days 3650 -in unsigned.csr -signkey private.key -out public.cert`
      File.delete("unsigned.csr") if File.exists?("unsigned.csr")
    end

    @context = OpenSSL::SSL::Context::Server.new
    @context.private_key = "private.key"
    @context.certificate_chain = "public.cert"

    unless File.exists?("blacklist.csv")
      File.write("blacklist.csv", "")
    end

    @blacklist = Set(BlacklistEntry).new
    File.read("blacklist.csv").each_line do |line|
      data = line.strip.split(',')

      if data.size != 4
        Log.error { "Incorrect number of values in blacklist.csv, ignoring entry `#{line}`" }
        next
      end

      username, address, mode, reason = data

      username = username.strip
      unless Woozy.valid_username?(username)
        Log.error { "Invalid username in blacklist.csv, ignoring entry `#{line}`" }
        next
      end

      address = address.strip
      unless Socket::IPAddress.valid?(address)
        Log.error { "Invalid address in blacklist.csv, ignoring entry `#{line}`" }
        next
      end

      mode = mode.strip
      case mode
      when "username"
        mode = BlacklistMode::Username
      when "address"
        mode = BlacklistMode::Address
      else
        Log.error { "Invalid mode in blacklist.csv, ignoring entry `#{line}`" }
        next
      end

      reason = reason.strip

      @blacklist << BlacklistEntry.new(username, address, mode, reason)
    end

    unless File.exists?("whitelist.csv")
      File.write("whitelist.csv", "")
    end

    @whitelist = Set(String).new
    File.read("whitelist.csv").each_line do |line|
      username = line.strip

      unless Woozy.valid_username?(username)
        Log.error { "Invalid username in whitelist.csv, ignoring entry `#{line}`" }
        next
      end

      @whitelist << username
    end

    @config = Hash(String, Bool | Float64 | Int32).new
    @config["whitelist"] = false

    unless File.exists?("server.cfg")
      config = String.build do |string|
        @config.each do |(key, value)|
          string << key
          string << '='
          string << value
          string << '\n'
        end
      end
      File.write("server.cfg", config)
    end

    File.read("server.cfg").each_line do |line|
      key, value = line.strip.split('=')
      key = key.strip
      value = value.strip

      if @config.has_key?(key)
        parsed_value = Woozy.parse_config_value(value)
        if !parsed_value.nil? && parsed_value.class == @config[key].class
          @config[key] = parsed_value
        else
          Log.error { "Invalid value `#{value}` for config key `#{key}` in server.cfg" }
        end
      else
        Log.error { "Unknown config key `#{key}` in server.cfg" }
      end
    end

    @char_channel = Channel(Chars).new
    @console_input = Array(Char).new
    @console_cursor = 0

    @world = World.new
    @world.set_chunk(Chunk.new(at: ChunkPos.new(0, 0, 0)))

    @tick = 0
  end

  def client_fiber : Nil
    while new_connection = @server.accept?
      client = FreshClient.new(new_connection)
      spawn @client_channel.send(client)
    end
  end

  def handle_fresh_client(fresh_client : FreshClient) : Nil
    bytes = Bytes.new(Packet::MaxSize)

    remote_address = if fresh_client.connection.closed?
      fresh_client.auth_channel.send(nil)
      return
    else
      fresh_client.connection.remote_address.to_s
    end

    bytes_read = 0
    begin
      OpenSSL::SSL::Socket::Server.open(fresh_client.connection, @context) do |ssl_connection|
        bytes_read = ssl_connection.read(bytes)
      end
    rescue ex : OpenSSL::SSL::Error
      cause = "Client does not trust unverified CA"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    if bytes_read.zero? # Connection was closed
      cause = "Client left"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.auth_channel.send(nil)
      return
    end

    packet = Packet.from_bytes(bytes[0...bytes_read].dup)

    unless packet
      cause = "Invalid handshake"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    unless client_handshake_packet = packet.client_handshake_packet
      cause = "Invalid handshake"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    unless username = client_handshake_packet.username
      cause = "Username is nil"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    unless password = client_handshake_packet.password
      cause = "Password is nil"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    unless Woozy.valid_username?(username)
      cause = "Username is not valid"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    if self.blacklisted?(username) || self.ip_blacklisted?(fresh_client.connection.remote_address.address)
      cause = "Client is blacklisted"
      Log.info &.emit "Disconnected client", address: remote_address, username: username, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    if @config["whitelist"] && !@whitelist.includes?(username)
      cause = "Client is not whitelisted"
      Log.info &.emit "Disconnected client", address: remote_address, username: username, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    DB.open("sqlite3://./server.db") do |db|
      db.exec("CREATE TABLE IF NOT EXISTS accounts (username varchar(32), password String)")
      db_username = db.query_one?("SELECT username FROM accounts WHERE username = ?", username, as: String)

      if db_username # Username exists, therefore client is logging in
        db_hashed_password = db.query_one("SELECT password FROM accounts WHERE username = ? LIMIT 1", username, as: String)

        unless Crypto::Bcrypt::Password.new(db_hashed_password).verify(password)
          cause = "Password is incorrect"
          Log.info &.emit "Disconnected client", address: remote_address, username: username, cause: cause
          fresh_client.connection.send(ServerDisconnectPacket.new(cause))
          fresh_client.connection.close
          fresh_client.auth_channel.send(nil)
          return
        end
      else # Username does not exist, therefore client is signing up
        hashed_password = Crypto::Bcrypt::Password.create(password, cost: 14)
        db.exec("INSERT INTO accounts (username, password) VALUES (?, ?)", username, hashed_password.to_s)
      end
    end

    if self.client_by_username(username)
      cause = "Client is already on the server"
      Log.info &.emit "Disconnected client", address: remote_address, username: username, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.connection.close
      fresh_client.auth_channel.send(nil)
      return
    end

    fresh_client.auth_channel.send(Client.new(fresh_client.connection, username))
  end

  def handle_client(client : Client) : Nil
    bytes = Bytes.new(Packet::MaxSize)

    until client.connection.closed?
      begin
        bytes_read, _ = client.connection.receive(bytes)
        break if bytes_read.zero? # Connection was closed
        packet = Packet.from_bytes(bytes[0...bytes_read].dup)
        spawn client.packet_channel.send(packet)
      rescue
        break
      end
    end
  end

  def handle_packet(client : Client, packet : Packet) : Nil
    case
    when client_disconnect_packet = packet.client_disconnect_packet
      Log.info &.emit "Client left", username: client.username
      @clients.delete(client)
    when client_private_message_packet = packet.client_private_message_packet
      sender = client.username
      recipient = client_private_message_packet.recipient
      message = client_private_message_packet.message

      if recipient && (client = self.client_by_username(recipient))
        Log.for("#{sender} > #{recipient}").info { message }
        client.connection.send(ServerPrivateMessagePacket.new(sender, message))
      end
    when client_broadcast_message_packet = packet.client_broadcast_message_packet
      sender = client.username
      message = client_broadcast_message_packet.message

      Log.for(sender).info { message }
      @clients.each do |other_client|
        if other_client.username != sender
          other_client.connection.send(ServerBroadcastMessagePacket.new(sender, message))
        end
      end
    end
  end

  alias Chars = StaticArray(Char, 4)

  enum KeyboardAction
    Stop
    Enter
    Backspace
    Delete
    Up
    Down
    Right
    Left
  end

  def char_fiber : Nil
    bytes = Bytes.new(4)
    loop do
      bytes_read = STDIN.read(bytes)

      chars = Chars.new('\0')
      bytes_read.times do |i|
        chars[i] = bytes[i].chr
        bytes[i] = 0u8
      end

      spawn @char_channel.send(chars)
    end
  end

  def handle_chars(chars : Chars) : KeyboardAction | Chars?
    case char0 = chars[0]
    when '\u{3}', '\u{4}'
      return KeyboardAction::Stop
    when '\n' # Enter
      return KeyboardAction::Enter
    when '\u{7f}' # Backspace
      return KeyboardAction::Backspace
    when '\e'
      case char1 = chars[1]
      when '['
        case char2 = chars[2]
        when 'A' # Up
          return KeyboardAction::Up
        when 'B' # Down
          return KeyboardAction::Down
        when 'C' # Right
          return KeyboardAction::Right
        when 'D' # Left
          return KeyboardAction::Left
        when '3'
          case char3 = chars[3]
          when '~' # Delete
            return KeyboardAction::Delete
          end
        end
      end

      return nil
    else
      return chars
    end
  end

  def clear_console_input : Nil
    print "\e[2K\r" # Clears current line, then returns text cursor to origin
  end

  def update_console_input : Nil
    print "> #{@console_input.join}\r\e[#{2 + @console_cursor}C"
  end

  def handle_keyboard_action(keyboard_action : KeyboardAction | Chars) : String?
    case keyboard_action
    when KeyboardAction::Stop
      self.stop
    when KeyboardAction::Enter
      command = @console_input.join
      @console_input.clear
      @console_cursor = 0
      return command
    when KeyboardAction::Backspace
      if (index = @console_cursor - 1) >= 0
        @console_input.delete_at(index)
        @console_cursor = Math.max(0, @console_cursor - 1)
      end
    when KeyboardAction::Delete
      if (index = @console_cursor) >= 0 && index < @console_input.size
        @console_input.delete_at(index)
      end
    when KeyboardAction::Up
    when KeyboardAction::Down
    when KeyboardAction::Right
      @console_cursor = Math.min(@console_input.size, @console_cursor + 1)
    when KeyboardAction::Left
      @console_cursor = Math.max(0, @console_cursor - 1)
    else
      chars = keyboard_action.as Chars
      chars.each do |char|
        if char != '\0'
          @console_input.insert(@console_cursor, char)
          @console_cursor = Math.min(@console_input.size, @console_cursor + 1)
        end
      end
    end

    nil
  end

  def handle_command(command : Array(String)) : Nil
    case command[0]?
    when "help"
      self.list_commands
    when "hello"
      Log.info { "world!" }
    when "stop"
      self.stop
    when "list"
      self.list_clients
    when "kick"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "kick <username>"
        return
      end

      self.kick_client(username)
    when "ban"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "ban <username> (reason)"
        return
      end

      reason = if command[2]?
        command[2..].join(' ')
      else
        ""
      end

      self.ban_client(username, reason)
    when "unban"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "unban <username>"
        return
      end

      self.unban_client(username)
    when "ban-ip"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "ban-ip <username> (reason)"
        return
      end

      reason = if command[2]?
        command[2..].join(' ')
      else
        ""
      end

      self.ban_ip(username, reason)
    when "unban-ip"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "unban-ip <username>"
        return
      end

      self.unban_ip(username)
    when "whitelist"
      case command[1]?
      when "add"
        unless (username = command[2]?) && Woozy.valid_username?(username)
          Log.error &.emit "Command syntax:", u1: "whitelist add <username>"
          return
        end

        Log.info { "Added `#{username}` to the whitelist" }
        @whitelist << username
      when "remove"
        unless (username = command[2]?) && Woozy.valid_username?(username)
          Log.error &.emit "Command syntax:", u1: "whitelist remove <username>"
          return
        end

        Log.info { "Removed `#{username}` from the whitelist" }
        @whitelist.delete(username)
      when "enable"
        Log.info { "Enabled the whitelist" }
        @config["whitelist"] = true
      when "disable"
        Log.info { "Disabled the whitelist" }
        @config["whitelist"] = false
      else
        Log.error &.emit "Command syntax:", u1: "whitelist add/remove <username>", u2: "whitelist enable/disable"
      end
    when "msg"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "msg <username> <message>"
        return
      end

      unless command[2]?
        Log.error &.emit "Command syntax:", u1: "msg <username> <message>"
        return
      end

      message = command[2..].join(' ')

      unless message.blank?
        self.private_message(username, message)
      end
    when "say"
      unless command[1]?
        Log.error &.emit "Command syntax:", u1: "say <message>"
        return
      end

      message = command[1..].join(' ')

      unless message.blank?
        self.broadcast_message(message)
      end
    else
      Log.error { "Unknown command `#{command.join(' ')}`" }
    end
  end

  def list_commands : Nil
    {% begin %}
    commands = String.build do |string|
    {% for method in Server.methods %}
    {% if method.name.symbolize == :handle_command %}
    {% commands = method.body.whens.map(&.conds.first) %}
    {% for command, index in commands %}
      string << {{command}}

      {% if index != commands.size - 1 %}
        string << ','
        string << ' '
      {% end %}
    {% end %}
    {% end %}
    {% end %}
    end
    {% end %}

    Log.info { "Available commands: #{commands}" }
  end

  def list_clients : Nil
    Log.info { @clients.map(&.username) }
  end

  def kick_client(username : String, reason = "") : Nil
    self.client_by_username(username) do |client|
      cause = "Kicked by operator for: #{reason}"
      Log.info &.emit "Disconnected client", username: client.username, cause: cause
      client.connection.send(ServerDisconnectPacket.new(cause))
      client.connection.close
      @clients.delete(client)
    end
  end

  def blacklisted?(username : String) : Bool
    blacklist_entry = @blacklist.find do |blacklist_entry|
      blacklist_entry.username == username && blacklist_entry.mode.username?
    end
    !blacklist_entry.nil?
  end

  def ip_blacklisted?(username : String) : Bool
    blacklist_entry = @blacklist.find do |blacklist_entry|
      blacklist_entry.username == username && blacklist_entry.mode.address?
    end
    !blacklist_entry.nil?
  end

  def ban_client(username : String, reason = "") : Nil
    self.client_by_username(username) do |client|
      @blacklist << BlacklistEntry.new(username, client.connection.remote_address.address, BlacklistMode::Username, reason)
      cause = "Banned by operator for: #{reason}"
      Log.info &.emit "Disconnected client", username: client.username, cause: cause
      client.connection.send(ServerDisconnectPacket.new(cause))
      client.connection.close
      @clients.delete(client)
    end
  end

  def unban_client(username : String) : Nil
    blacklist_entry = @blacklist.find do |blacklist_entry|
      blacklist_entry.username == username && blacklist_entry.mode.username?
    end
    @blacklist.delete(blacklist_entry) if blacklist_entry
  end

  def ban_ip(username : String, reason = "") : Nil
    self.client_by_username(username) do |client|
      @blacklist << BlacklistEntry.new(username, client.connection.remote_address.address, BlacklistMode::Address, reason)
      cause = "Banned by operator for: #{reason}"
      Log.info &.emit "Disconnected client", username: client.username, cause: cause
      client.connection.send(ServerDisconnectPacket.new(cause))
      client.connection.close
      @clients.delete(client)
    end
  end

  def unban_ip(username : String) : Nil
    blacklist_entry = @blacklist.find do |blacklist_entry|
      blacklist_entry.username == username && blacklist_entry.mode.address?
    end
    @blacklist.delete(blacklist_entry) if blacklist_entry
  end

  def private_message(recipient : String, message : String)
    self.client_by_username(recipient) do |client|
      Log.for("#{Username} > #{recipient}").info { message }
      client.connection.send(ServerPrivateMessagePacket.new(Username, message))
    end
  end

  def broadcast_message(message : String) : Nil
    Log.for(Username).info { message }
    @clients.each do |client|
      client.connection.send(ServerBroadcastMessagePacket.new(Username, message))
    end
  end

  def client_by_username(username : String, & : Client ->) : Nil
    if client = self.client_by_username(username)
      yield client
    else
      Log.error { "Could not find client with username `#{username}`" }
    end
  end

  def client_by_username(username : String) : Client?
    @clients.find do |client|
      client.username == username
    end
  end

  def start : Nil
    Woozy.set_terminal_mode

    Log.info { "Server started" }
    self.update_console_input

    spawn self.char_fiber
    spawn self.client_fiber

    loop do
      select
      when timeout(50.milliseconds)
        self.clear_console_input
        self.update
        self.update_console_input
      end
    end
  end

  def update : Nil
    # Check for new clients
    loop do
      select # Non-blocking, raising receive
      when fresh_client = @client_channel.receive
        @fresh_clients << fresh_client
        spawn self.handle_fresh_client(fresh_client)
      else
        break # All clients received
      end
    end

    # Check for clients which have authenticated themselves
    @fresh_clients.reject! do |fresh_client|
      select # Non-blocking, raising receive
      when authenticated = fresh_client.auth_channel.receive
        if client = authenticated
          Log.info &.emit "Client joined", address: client.connection.remote_address.to_s, username: client.username
          @clients << client
          spawn self.handle_client(client)
          client.connection.send(ServerHandshakePacket.new)
        end

        true
      else
        false
      end
    end

    # Check for new packets
    @clients.each do |client|
      loop do
        select # Non-blocking, raising receive
        when packet = client.packet_channel.receive
          self.handle_packet(client, packet)
        else
          break # All packets received, next client
        end
      end
    end

    # Check for new chars
    select
    when chars = @char_channel.receive
      if keyboard_action = self.handle_chars(chars)
        command = self.handle_keyboard_action(keyboard_action)
        self.handle_command(command.split(' ')) if command && !command.blank? && !command.empty?
      end
    else
    end

    @tick += 1
  end

  def stop : NoReturn
    Log.info { "Server stopped" }

    cause = "Server stopped"
    @clients.each do |client|
      client.connection.send(ServerDisconnectPacket.new(cause))
      client.connection.close
    end

    blacklist = String.build do |string|
      @blacklist.each_with_index do |blacklist_entry, index|
        string << blacklist_entry.username
        string << ','
        string << blacklist_entry.address
        string << ','
        string << blacklist_entry.mode.to_s.downcase
        string << ','
        string << blacklist_entry.reason
        string << '\n' if index != @blacklist.size - 1
      end
    end

    File.write("blacklist.csv", blacklist)
    File.write("whitelist.csv", @whitelist.join('\n'))

    config = String.build do |string|
      @config.each_with_index do |(key, value), index|
        string << key
        string << '='
        string << value
        string << '\n' if index != @config.keys.size - 1
      end
    end
    File.write("server.cfg", config)

    exit
  end
end
