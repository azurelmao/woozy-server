struct Woozy::Packet
  def self.from_client(client : Client)
    Packet.from_socket(client.socket)
  end
end

struct Client
  getter socket : TCPSocket
  getter username : String

  delegate close, send, local_address, to: @socket

  def initialize(@socket, @username)
  end
end

struct Woozy::Server
  def client_loop(channel : Channel({Client, Packet}))
    while socket = @tcp_server.accept?
      unless packet = Packet.from_socket(socket)
        next
      end

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
        client = Client.new socket, username
        @clients[username] = client
        client.send ServerHandshakePacket.new

        spawn packet_loop(channel, client)
      end
    end
  end

  def packet_loop(channel : Channel({Client, Packet}), client : Client)
    loop do
      if packet = Packet.from_client(client)
        channel.send({client, packet})
      else
        channel.close
        break
      end
    end
  end

  def handle_packet(client : Client, packet : Packet)
    case
    when client_disconnect_packet = packet.client_disconnect_packet
      username = client.username
      Log.info &.emit "Client left the server", addr: client.local_address.address, username: username
      client.close
      @clients.delete(username)
    when client_message_packet = packet.client_message_packet
      Log.info &.emit "#{client.username} - #{client_message_packet.message}"
    else
      Log.error &.emit "Huh?", packet: packet.to_s
    end
  end
end
