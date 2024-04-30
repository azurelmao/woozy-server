struct Woozy::Server
  def client_loop(channel : Channel({Client, Packet}))
    while socket = @tcp_server.accept?
      unless packet = Packet.from_socket(socket)
        next
      end


      client_handshake_packet = packet.client_handshake_packet
      if client_handshake_packet.nil?
        cause = "Invalid handshake"
        Log.info &.emit "Server disconnected client", addr: socket.local_address.address, cause: cause
        socket.send Packet.new server_disconnect_packet: ServerDisconnectPacket.new cause
        next
      end

      username = client_handshake_packet.username
      if username.nil?
        cause = "Username is nil"
        Log.info &.emit "Server disconnected client", addr: socket.local_address.address, cause: cause
        socket.send Packet.new server_disconnect_packet: ServerDisconnectPacket.new cause
        next
      end

      if @clients[username]?
        cause = "`#{username}` is already on the server"
        Log.info &.emit "Handshake rejected", addr: socket.local_address.address, username: username, cause: cause
        socket.send Packet.new server_disconnect_packet: ServerDisconnectPacket.new cause
      else
        Log.info &.emit "Handshake accepted", addr: socket.local_address.address, username: username
        socket.send Packet.new server_handshake_packet: ServerHandshakePacket.new
        client = Client.new socket, username
        @clients[username] = client

        spawn do
          loop do
            packet = Packet.from_socket(socket)
            break if packet.nil?
            channel.send({client, packet.not_nil!})
          end
        end
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
    else
      Log.error &.emit "Huh?", packet: packet.to_s
    end
  end
end
