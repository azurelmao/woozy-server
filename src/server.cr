require "woozy"
require "./world/world"
require "./command"
require "./network"

struct Woozy::Server
  def initialize(host : String, port : Int32)
    @tcp_server = TCPServer.new host, port
    @clients = Hash(String, Client).new

    @command_history = Chronicle.new

    @world = World.new
    @world.set_chunk Chunk.new at: ChunkPos.new(0, 0, 0)

    @tick = 0
  end

  def start : Nil
    command_channel = Channel(Command).new
    spawn self.key_loop(command_channel)
    Fiber.yield

    packet_channel = Channel({Client, Packet}).new
    spawn self.client_loop(packet_channel)
    Fiber.yield

    Log.info { "Server started!" }

    self.clear_line
    loop do
      select
      when timeout(1.second)
        self.clear_line

        loop do
          select
          when client_and_packet = packet_channel.receive
            client, packet = client_and_packet
            self.handle_packet(client, packet)
          else
            break
          end
        end

        loop do
          select
          when command = command_channel.receive
            self.handle_command(command)
          else
            break
          end
        end

        update

        self.print_current_line
      end
    end
  end

  def update : Nil
    Log.info { @clients.keys }
    @tick += 1
  end

  def stop : Nil
    Log.info { "Stopping server!" }

    @clients.each_value do |client|
      Log.info &.emit "Disconnected client", addr: client.local_address.address, username: client.username
      client.send ServerDisconnectPacket.new "Server stopped!"
      client.stop

    end

    Log.info { "Server stopped!" }

    exit
  end
end

raise "Mismatched number of arguments!" if ARGV.size.odd?

host = "127.0.0.1"
port = 1234

index = 0
while index < ARGV.size
  case ARGV[index]
  when "-h", "--host"
    host = ARGV[index + 1]
  when "-p", "--port"
    port = ARGV[index + 1].to_i
  end
  index += 2
end

server = Woozy::Server.new host, port
server.start
