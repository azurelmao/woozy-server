require "woozy"
require "sqlite3"
require "crypto/bcrypt/password"
require "./blacklist"
require "./whitelist"
require "./fresh_client_receiver_actor"
require "./client_actor"
require "./content"

struct Command
  def initialize(@args : Array(String))
  end

  forward_missing_to @args
end

class Woozy::ServerActor
  Username = "[Server]"

  def initialize(host : String, port : Int32)
    @log_channel = Channel(Log::Entry).new

    Woozy.setup_terminal_mode
    Woozy.setup_logs(@log_channel)

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

      [v3_req]
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

    @blacklist = Blacklist.new("blacklist.csv")
    @whitelist = Whitelist.new("whitelist.txt")

    @server_config = SimpleConfig(Bool | Float64 | Int32).new("server.cfg", {"whitelist" => false}) do |value|
      case value
      when "true"  then true
      when "false" then false
      when .to_i?  then value.to_i
      when .to_f?  then value.to_f
      else
        nil
      end
    end

    @stop_channel = Channel(Nil).new
    @command_channel = Channel(Command).new
    @change_channel = Channel(ConsoleInputActor::Change).new
    @content = Content.new

    @console_input_actor = ConsoleInputActor.new(@stop_channel, @command_channel, @change_channel)
    @console_output_actor = ConsoleOutputActor.new(@change_channel, @log_channel)

    server = TCPServer.new(host, port)
    context = OpenSSL::SSL::Context::Server.new
    context.private_key = "private.key"
    context.certificate_chain = "public.cert"
    @fresh_client_channel = Channel(FreshClient).new
    @fresh_client_receiver_actor = FreshClientReceiverActor.new(server, context, @fresh_client_channel)

    @clients_currently_authenticating = Set(String).new
    @client_actor_channel = Channel(ClientActor | String).new
    @client_actors = Array(ClientActor).new

    @height_map = Array(Int32).new(Chunk::Area, 0)
    LocalPosXZ.new(0, 0).to LocalPosXZ.new(Chunk::BitMask, Chunk::BitMask) do |local_pos|
      @height_map[local_pos.index] = Random.rand(2..4)
    end

    @chunks = Hash(ChunkPos, Chunk).new
    @chunks[ChunkPos.new(0, 0, 0)] = ServerActor.generate_chunk(@content, @height_map, ChunkPos.new(0, 0, 0))
    @chunks[ChunkPos.new(-1, 0, 0)] = ServerActor.generate_chunk(@content, @height_map, ChunkPos.new(-1, 0, 0))
    @chunks[ChunkPos.new(-1, 0, -1)] = ServerActor.generate_chunk(@content, @height_map, ChunkPos.new(-1, 0, -1))
    @chunks[ChunkPos.new(0, 0, -1)] = ServerActor.generate_chunk(@content, @height_map, ChunkPos.new(0, 0, -1))

    @tick = 0
  end

  def self.generate_chunk(content : Content, height_map : Array(Int32), chunk_pos : ChunkPos) : Chunk
    chunk = Chunk.new(chunk_pos, Block.new(content.blocks.air))

    LocalPos.new(0, 0, 0).to LocalPos.new(Chunk::BitMask, Chunk::BitMask, Chunk::BitMask) do |local_pos|
      height = height_map[local_pos.to_xz.index]

      if local_pos.y < height
        chunk.set_block(local_pos, Block.new(content.blocks.stone))
      elsif local_pos.y == height
        chunk.set_block(local_pos, Block.new(content.blocks.grass))
      end
    end

    chunk
  end

  def list_clients : Nil
    Log.info { @client_actors.map(&.username) }
  end

  def kick_client(username : String, reason = "") : Nil
    self.get_client(username) do |client|
      cause = if reason.empty?
        "Kicked by operator"
      else
        "Kicked by operator for `#{reason}`"
      end

      Log.info &.emit "Disconnected client", username: client.username, cause: cause
      client.socket.send(ServerDisconnectPacket.new(cause))
      client.socket.close
      @client_actors.delete(client)
    end
  end

  def ban_client(username : String, reason = "") : Nil
    self.get_client(username) do |client|
      cause = if reason.empty?
        "Banned by operator"
      else
        "Banned by operator for `#{reason}`"
      end

      Log.info &.emit "Disconnected client", username: client.username, cause: cause
      client.socket.send(ServerDisconnectPacket.new(cause))
      client.socket.close
      @client_actors.delete(client)
      @blacklist << Blacklist::Entry.new(username, client.socket.remote_address.address, Blacklist::Mode::Username, reason)
    end
  end

  def unban_client(username : String) : Nil
    if blacklist_entry = @blacklist.find do |blacklist_entry| blacklist_entry.username == username end
      if blacklist_entry.mode.address?
        Log.info &.emit "Unbanned #{blacklist_entry.username}"
          @blacklist.delete(blacklist_entry) if blacklist_entry
      else
        Log.error &.emit "Client #{blacklist_entry.username} is not banned"
      end
    else
      Log.error &.emit "Client #{username} is not banned"
    end
  end

  def ban_ip(username : String, reason = "") : Nil
    self.get_client(username) do |client|

      cause = if reason.empty?
        "Banned by operator"
      else
        "Banned by operator for `#{reason}`"
      end

      Log.info &.emit "Disconnected client", username: client.username, cause: cause
      client.socket.send(ServerDisconnectPacket.new(cause))
      client.socket.close
      @client_actors.delete(client)
      @blacklist << Blacklist::Entry.new(username, client.socket.remote_address.address, Blacklist::Mode::Address, reason)
    end
  end

  def unban_ip(username : String) : Nil
    if blacklist_entry = @blacklist.find do |blacklist_entry| blacklist_entry.username == username end
      if blacklist_entry.mode.address?
        Log.info &.emit "IP unbanned #{blacklist_entry.username}"
        @blacklist.delete(blacklist_entry) if blacklist_entry
      else
        Log.error &.emit "Client #{blacklist_entry.username} is not ip-banned"
      end
    else
      Log.error &.emit "Client #{username} is not ip-banned"
    end
  end

  def private_message(recipient : String, message : String)
    self.get_client(recipient) do |client|
      Log.for("#{Username} > #{recipient}").info { message }
      client.socket.send(ServerPrivateMessagePacket.new(Username, message))
    end
  end

  def broadcast_message(message : String) : Nil
    Log.for(Username).info { message }
    @client_actors.each do |client|
      client.socket.send(ServerBroadcastMessagePacket.new(Username, message))
    end
  end

  def get_client(username : String, & : ClientActor ->) : Nil
    if client = self.get_client(username)
      yield client
    else
      Log.error { "Could not find client with username `#{username}`" }
    end
  end

  def get_client(username : String) : ClientActor?
    @client_actors.find do |client|
      client.username == username
    end
  end

  def handle_command(command : Command) : Nil
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
        Log.error &.emit "Command syntax:", u1: "kick #{Woozy.highlight_error("<username>")}"
        return
      end

      self.kick_client(username)
    when "ban"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "ban #{Woozy.highlight_error("<username>")} (reason)"
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
        Log.error &.emit "Command syntax:", u1: "unban #{Woozy.highlight_error("<username>")}"
        return
      end

      self.unban_client(username)
    when "ban-ip"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "ban-ip #{Woozy.highlight_error("<username>")} (reason)"
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
        Log.error &.emit "Command syntax:", u1: "unban-ip #{Woozy.highlight_error("<username>")}"
        return
      end

      self.unban_ip(username)
    when "whitelist"
      case command[1]?
      when "add"
        unless (username = command[2]?) && Woozy.valid_username?(username)
          Log.error &.emit "Command syntax:", u1: "whitelist add #{Woozy.highlight_error("<username>")}"
          return
        end

        Log.info { "Added `#{username}` to the whitelist" }
        @whitelist << username
      when "remove"
        unless (username = command[2]?) && Woozy.valid_username?(username)
          Log.error &.emit "Command syntax:", u1: "whitelist remove #{Woozy.highlight_error("<username>")}"
          return
        end

        Log.info { "Removed `#{username}` from the whitelist" }
        @whitelist.delete(username)
      when "enable"
        Log.info { "Enabled the whitelist" }
        @server_config["whitelist"] = true
      when "disable"
        Log.info { "Disabled the whitelist" }
        @server_config["whitelist"] = false
      else
        Log.error &.emit "Command syntax:", u1: "whitelist add/remove <username>", u2: "whitelist enable/disable"
      end
    when "msg"
      unless (username = command[1]?) && Woozy.valid_username?(username)
        Log.error &.emit "Command syntax:", u1: "msg #{Woozy.highlight_error("<username>")} <message>"
        return
      end

      unless command[2]?
        Log.error &.emit "Command syntax:", u1: "msg <username> #{Woozy.highlight_error("<message>")}"
        return
      end

      message = command[2..].join(' ')

      unless message.blank?
        self.private_message(username, message)
      end
    when "say"
      unless command[1]?
        Log.error &.emit "Command syntax:", u1: "say #{Woozy.highlight_error("<message>")}"
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
    {% for method in ServerActor.methods %}
      {% if method.name.symbolize == :handle_command %}
        {% for when, when_index in method.body.whens %}
          {% for cond, cond_index in when.conds %}
            string << {{cond}}

            {% if cond_index != when.conds.size - 1 %}
              string << ','
              string << ' '
            {% end %}
          {% end %}

          {% if when_index != method.body.whens.size - 1 %}
              string << ','
              string << ' '
            {% end %}
        {% end %}
      end

      Log.info { "Available commands: #{commands}" }
      {% end %}
    {% end %}
    {% end %}
  end

  def handle_fresh_client(fresh_client : FreshClient) : Nil
    socket = fresh_client.socket
    address = socket.remote_address.address
    username = fresh_client.username

    if (blacklist_entry = @blacklist.blacklisted?(username) || @blacklist.ip_blacklisted?(address))
      cause = if blacklist_entry.reason.empty?
                "Client is blacklisted"
              else
                "Client is blacklisted for `#{blacklist_entry.reason}`"
              end

      Log.info &.emit "Disconnected client", address: address, username: username, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    if @server_config["whitelist"] && !@whitelist.includes?(username)
      cause = "Client is not whitelisted"
      Log.info &.emit "Disconnected client", address: address, username: username, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    if self.get_client(username) || @clients_currently_authenticating.includes?(username)
      cause = "Client is already on the server"
      Log.info &.emit "Disconnected client", address: address, username: username, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    @clients_currently_authenticating << username
    spawn self.auth_fresh_client(fresh_client)
  end

  def auth_fresh_client(fresh_client : FreshClient) : Nil
    socket = fresh_client.socket
    address = socket.remote_address.address
    username = fresh_client.username
    password = fresh_client.password

    DB.open("sqlite3://./server.db") do |db|
      db.exec("CREATE TABLE IF NOT EXISTS accounts (username varchar(32), password String)")
      db_username = db.query_one?("SELECT username FROM accounts WHERE username = ?", username, as: String)

      if db_username # Username exists, therefore client is logging in
        db_hashed_password = db.query_one("SELECT password FROM accounts WHERE username = ? LIMIT 1", username, as: String)

        unless Crypto::Bcrypt::Password.new(db_hashed_password).verify(password)
          cause = "Password is incorrect"
          Log.info &.emit "Disconnected client", address: address, username: username, cause: cause
          socket.send(ServerDisconnectPacket.new(cause))
          socket.close
          @client_actor_channel.send(username)
          return
        end
      else # Username does not exist, therefore client is signing up
        hashed_password = Crypto::Bcrypt::Password.create(password, cost: 14)
        db.exec("INSERT INTO accounts (username, password) VALUES (?, ?)", username, hashed_password.to_s)
      end
    end

    @client_actor_channel.send(ClientActor.new(socket, username))
  end

  def handle_packet(client : ClientActor, packet : Packet) : Nil
    case packet
    when ClientDisconnectPacket
      Log.info &.emit "Client left", username: client.username
      @client_actors.delete(client)
    when ClientPrivateMessagePacket
      sender = client.username
      recipient = packet.recipient
      message = packet.message

      if recipient_client = self.get_client(recipient)
        Log.for("#{sender} > #{recipient}").info { message }
        recipient_client.socket.send(ServerPrivateMessagePacket.new(sender, message))
        client.socket.send(ServerPrivateMessageSuccessPacket.new(recipient, message, true))
      else
        client.socket.send(ServerPrivateMessageSuccessPacket.new(recipient, message, false))
      end
    when ClientBroadcastMessagePacket
      sender = client.username
      message = packet.message

      Log.for(sender).info { message }
      @client_actors.each do |other_client|
        if other_client.username != sender
          other_client.socket.send(ServerBroadcastMessagePacket.new(sender, message))
        end
      end
    end
  end

  def handle_client(client : ClientActor) : Nil
    Log.info &.emit "Client joined", username: client.username
    @clients_currently_authenticating.delete(client.username)
    @client_actors << client
    client.socket.send(ServerHandshakePacket.new)
    spawn client.start

    @chunks.each_value do |chunk|
      x, y, z = chunk.position.splat

      block_palette = Hash(UInt16, String).new
      chunk.block_palette.to_a do |key, block|
        block_palette[key] = @content.blocks.name_of(block.index)
      end

      block_ids = chunk.block_ids
      client.socket.send(ServerChunkPacket.new(x, y, z, block_palette, block_ids))
    end
  end

  def start : Nil
    Log.info { "Server started" }

    spawn @console_input_actor.start
    spawn @console_output_actor.start
    spawn @fresh_client_receiver_actor.start

    loop do
      select
      when @stop_channel.receive
        self.stop
      when timeout(50.milliseconds)
        self.update
      end
    end
  end

  def update : Nil
    loop do
      select # Non-blocking, raising receive
      when fresh_client = @fresh_client_channel.receive
        self.handle_fresh_client(fresh_client)
      else
        break
      end
    end

    loop do
      select # Non-blocking, raising receive
      when client_actor_or_username = @client_actor_channel.receive
        case client_actor_or_username
        when ClientActor
          client_actor = client_actor_or_username.as ClientActor
          self.handle_client(client_actor)
        when String
          username = client_actor_or_username.as String
          @clients_currently_authenticating.delete(username)
        end
      else
        break
      end
    end

    @client_actors.each do |client|
      loop do
        select # Non-blocking, raising receive
        when packet = client.packet_channel.receive
          self.handle_packet(client, packet)
        else
          break # All packets received, next client
        end
      end
    end

    # Check for new commands
    loop do
      select # Non-blocking, raising receive
      when command = @command_channel.receive
        self.handle_command(command)
      else
        break # All commands received
      end
    end

    @tick += 1
  end

  def stop : NoReturn
    cause = "Server stopped"
    @client_actors.each do |client|
      client.socket.send(ServerDisconnectPacket.new(cause))
      client.socket.close
    end

    @console_output_actor.stop
    @blacklist.write
    @whitelist.write

    @server_config.write

    exit
  end
end
