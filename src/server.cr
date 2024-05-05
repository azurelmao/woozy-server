require "woozy"
require "./world/world"
require "./command"
require "./network"

struct Woozy::Server
  def initialize(host : String, port : Int32)
    @tcp_server = TCPServer.new host, port
    @clients = Hash(String, Client).new

    @tick = 0

    @command_history = Chronicle.new

    @world = World.new
    @world.set_chunk Chunk.new at: ChunkPos.new(0, 0, 0)
  end

  def start
    command_channel = Channel(Command).new
    spawn key_loop(command_channel)
    Fiber.yield

    packet_channel = Channel({Client, Packet}).new
    spawn client_loop(packet_channel)
    Fiber.yield

    Log.info { "Server started!" }

    print "> "
    loop do
      select
      when timeout(1.second)
        print "\e[2K\r"

        loop do
          select
          when client_and_packet = packet_channel.receive?
            next unless client_and_packet
            client, packet = client_and_packet
            handle_packet(client, packet)
          else
            break
          end
        end

        loop do
          select
          when command = command_channel.receive
            handle_command(command)
          else
            break
          end
        end

        update

        print "> #{@command_history.current_record.join}\r\e[#{2 + @command_history.cursor_index}C"
      end
    end
  end

  def update
    Log.info { @clients }
    @tick += 1
  end

  def stop
    Log.info { "Server stopped!" }

    @clients.each_value do |client|
      client.send ServerDisconnectPacket.new "Server stopped!"
      client.close
    end

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
