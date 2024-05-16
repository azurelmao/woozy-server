struct Woozy::Client
  getter username : String
  delegate send, local_address, to: @socket

  def initialize(@socket : TCPSocket, @username, @packet_channel : Channel({Client, Packet}))
    @stop_channel = Channel(Bool).new
  end

  def stop : Nil
    select
    when @stop_channel.send true
    else
    end
  end

  def packet_loop : Nil
    bytes = Bytes.new(Packet::MaxSize)

    until @socket.closed?
      select
      when @stop_channel.receive then break
      else
      end

      bytes_read, _ = @socket.receive(bytes)
      break if bytes_read.zero? # Socket was closed
      packet = Packet.from_bytes(bytes[0...bytes_read].dup)

      @packet_channel.send({self, packet})
    end
  end
end

struct Woozy::Server
  def client_loop(packet_channel : Channel({Client, Packet})) : Nil
    bytes = Bytes.new(Packet::MaxSize)

    while socket = @tcp_server.accept?
      next if socket.closed?
      bytes_read, _ = socket.receive(bytes)
      next if bytes_read.zero? # Socket was closed
      packet = Packet.from_bytes(bytes[0...bytes_read].dup)

      unless client_handshake_packet = packet.client_handshake_packet
        cause = "Invalid handshake"
        Log.info &.emit "Server disconnected client", addr: socket.local_address.address, cause: cause
        socket.send ServerDisconnectPacket.new cause
        next
      end

      unless username = client_handshake_packet.username
        cause = "Username is nil"
        Log.info &.emit "Server disconnected client", addr: socket.local_address.address, cause: cause
        socket.send ServerDisconnectPacket.new cause
        next
      end

      if @clients[username]?
        cause = "`#{username}` is already on the server"
        Log.info &.emit "Handshake rejected", addr: socket.local_address.address, username: username, cause: cause
        socket.send ServerDisconnectPacket.new cause
      else
        Log.info &.emit "Handshake accepted", addr: socket.local_address.address, username: username

        client = Client.new socket, username, packet_channel
        @clients[username] = client

        spawn client.packet_loop
        client.send ServerHandshakePacket.new
      end
    end
  end

  def handle_packet(client : Client, packet : Packet) : Nil
    case
    when client_disconnect_packet = packet.client_disconnect_packet
      username = client.username
      Log.info &.emit "Client left the server", addr: client.local_address.address, username: username
      self.delete_client(client)
    when client_message_packet = packet.client_message_packet
      Log.for(client.username).info &.emit "#{client_message_packet.message}"
    else
      Log.error &.emit "Huh?", packet: packet.to_s
    end
  end

  def delete_client(client : Client) : Nil
    client.stop
    @clients.delete(client.username)
  end
end
