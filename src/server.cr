require "woozy"
require "socket"
require "./util/timer"
require "./world/world"
require "./key_fiber"
require "./client"
require "./network"

struct Woozy::Server
  def initialize(host : String, port : Int32)
    @tcp_server = TCPServer.new host, port
    @clients = Hash(String, Client).new

    @timer = Timer.new(1.second)
    @tick = 0

    @command_history = Array(Array(Char)).new
    @command_history << [] of Char
    @command_index = 0
    @cursor_pos = 0

    @world = World.new
    @world.set_chunk Chunk.new at: ChunkPos.new(0, 0, 0)
  end

  def start
    set_terminal_mode

    Log.info { "Server started!" }

    inbound_channel = Channel({Client, Packet}).new
    spawn client_loop(inbound_channel)

    key_channel = Channel(Char | Key).new
    spawn key_loop(key_channel)

    print "> "
    loop do
      select
      when client_and_packet = inbound_channel.receive
        print "\e[2K\r"

        client, packet = client_and_packet
        handle_packet(client, packet)

        print "> #{@command_history[@command_index].join}\r\e[#{2 + @cursor_pos}C"
      when key = key_channel.receive
        print "\e[2K\r"

        case key
        when Char
          if @command_history[@command_index][@cursor_pos]?
            @command_history[@command_index].insert(@cursor_pos, key)
          else
            @command_history[@command_index] << key
          end

          @cursor_pos += 1
        when .enter?
          handle_command(@command_history[@command_index].join)

          @command_history << [] of Char unless @command_history.last.empty?

          if @command_index < @command_history.size - 1
            @command_index = @command_history.size - 1
          else
            @command_index += 1
          end

          @cursor_pos = 0
        when .backspace?
          if @cursor_pos > 0
            if @command_history[@command_index][@cursor_pos - 1]?
              @command_history[@command_index].delete_at(@cursor_pos - 1)
            else
              @command_history[@command_index].pop?
            end

            @cursor_pos -= 1
          end
        when .delete?
          if @cursor_pos < @command_history[@command_index].size
            if @command_history[@command_index][@cursor_pos]?
              @command_history[@command_index].delete_at(@cursor_pos)
            else
              @command_history[@command_index].pop?
            end
          end
        when .up?
          @command_index -= 1 if @command_index > 0
        when .down?
          @command_index += 1 if @command_index < @command_history.size - 1
        when .right?
          @cursor_pos += 1 if @cursor_pos < @command_history[@command_index].size
        when .left?
          @cursor_pos -= 1 if @cursor_pos > 0
        end

        print "> #{@command_history[@command_index].join}\r\e[#{2 + @cursor_pos}C"
      else
        @timer.run do
          print "\e[2K\r"

          update

          print "> #{@command_history[@command_index].join}\r\e[#{2 + @cursor_pos}C"
        end
      end
    end
  end

  def stop
    Log.info { "Server stopped!" }

    @clients.each_value do |client|
      client.send Packet.new server_disconnect_packet: ServerDisconnectPacket.new "Server stopped!"
    end

    exit
  end

  def update
    Log.info { @clients }
    @tick += 1
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
