struct Woozy::FreshClient
  getter socket : TCPSocket
  getter username : String
  getter password : String

  def initialize(@socket, @username, @password)
  end
end

class Woozy::FreshClientReceiverActor
  @server : TCPServer
  @context : OpenSSL::SSL::Context::Server
  @fresh_client_channel : Channel(FreshClient)

  def initialize(@server, @context, @fresh_client_channel)
  end

  def start : Nil
    while socket = @server.accept?
      spawn self.handle_new_socket(socket)
    end
  end

  def handle_new_socket(socket : TCPSocket) : Nil
    remote_address = if socket.closed?
                     else
                       socket.remote_address.to_s
                     end

    id = uninitialized UInt8
    bytes = uninitialized Bytes

    begin
      OpenSSL::SSL::Socket::Server.open(socket, @context) do |ssl_socket|
        header = uninitialized StaticArray(UInt8, Packet::HeaderSize)
        unless ssl_socket.read_fully(header.to_slice)
          cause = "Client left"
          Log.info &.emit "Disconnected client", address: remote_address, cause: cause
          return
        end

        id, size = Packet.header_from_bytes(header.to_slice)
        bytes = Bytes.new(size)

        unless ssl_socket.read_fully?(bytes)
          cause = "Invalid handshake"
          Log.info &.emit "Disconnected client", address: remote_address, cause: cause
          socket.send(ServerDisconnectPacket.new(cause))
          socket.close
          return
        end
      end
    rescue ex : OpenSSL::SSL::Error
      cause = "Client does not trust unverified CA"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    packet = Packet.from_id(id, bytes)

    unless packet
      cause = "Invalid handshake"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    unless packet.is_a? ClientHandshakePacket
      cause = "Invalid handshake"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    unless username = packet.username
      cause = "Username is nil"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    unless Woozy.valid_username?(username)
      cause = "Username is not valid"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    unless password = packet.password
      cause = "Password is nil"
      Log.info &.emit "Disconnected client", address: remote_address, cause: cause
      socket.send(ServerDisconnectPacket.new(cause))
      socket.close
      return
    end

    @fresh_client_channel.send(FreshClient.new(socket, username, password))
  end
end
