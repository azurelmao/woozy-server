class Woozy::ClientActor
  getter socket : TCPSocket
  getter packet_channel : Channel(Packet)
  getter username : String

  def initialize(@socket, @username)
    @packet_channel = Channel(Packet).new
  end

  def start
    bytes = Bytes.new(Packet::DefaultSize)

    until @socket.closed?
      begin
        header = uninitialized StaticArray(UInt8, Packet::HeaderSize)
        break unless @socket.read_fully?(header.to_slice)

        id, size = Packet.header_from_bytes(header.to_slice)
        if bytes.size < size
          bytes = Bytes.new(GC.realloc(bytes.to_unsafe, size), size)
        end

        @socket.read_fully(bytes[0...size])
        break unless packet = Packet.from_id(id, bytes[0...size])

        spawn @packet_channel.send(packet)
      rescue ex
        Log.fatal(exception: ex) {""}
        break
      end
    end
  end
end
