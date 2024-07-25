require "woozy"
require "./world/world"

class Woozy::FreshClient
  property connection : TCPSocket
  property auth_channel = Channel(String?).new

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

struct Woozy::Server
  def initialize(host : String, port : Int32)
    @server = TCPServer.new(host, port)
    @client_channel = Channel(FreshClient).new
    @fresh_clients = Array(FreshClient).new
    @clients = Array(Client).new

    @char_channel = Channel(Chars).new
    @console_input = Array(Char).new
    @console_cursor = 0

    @world = World.new
    @world.set_chunk Chunk.new at: ChunkPos.new(0, 0, 0)

    @tick = 0
  end

  def set_terminal_mode : Nil
    before = Crystal::System::FileDescriptor.tcgetattr STDIN.fd
    mode = before
    mode.c_lflag &= ~LibC::ICANON
    mode.c_lflag &= ~LibC::ECHO
    mode.c_lflag &= ~LibC::ISIG

    at_exit do
      Crystal::System::FileDescriptor.tcsetattr(STDIN.fd, LibC::TCSANOW, pointerof(before))
    end

    if Crystal::System::FileDescriptor.tcsetattr(STDIN.fd, LibC::TCSANOW, pointerof(mode)) != 0
      raise IO::Error.from_errno "tcsetattr"
    end
  end

  def client_fiber : Nil
    while new_connection = @server.accept?
      client = FreshClient.new(new_connection)
      spawn @client_channel.send(client)
    end
  end

  def handle_fresh_client(fresh_client : FreshClient) : Nil
    bytes = Bytes.new(Packet::MaxSize)

    if fresh_client.connection.closed?
      fresh_client.auth_channel.send(nil)
      return
    end
    bytes_read, _ = fresh_client.connection.receive(bytes)
    if bytes_read.zero? # Connection was closed
      fresh_client.auth_channel.send(nil)
      return
    end
    packet = Packet.from_bytes(bytes[0...bytes_read].dup)

    unless client_handshake_packet = packet.client_handshake_packet
      cause = "Invalid handshake"
      Log.info &.emit "Disconnected client", addr: fresh_client.connection.local_address.address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.auth_channel.send(nil)
      return
    end

    unless username = client_handshake_packet.username
      cause = "Username is nil"
      Log.info &.emit "Disconnected client", addr: fresh_client.connection.local_address.address, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.auth_channel.send(nil)
      return
    end

    if @clients.find { |client| client.username == username }
      cause = "`#{username}` is already on the server"
      Log.info &.emit "Handshake rejected", addr: fresh_client.connection.local_address.address, username: username, cause: cause
      fresh_client.connection.send(ServerDisconnectPacket.new(cause))
      fresh_client.auth_channel.send(nil)
      return
    end

    Log.info &.emit "Handshake accepted", addr: fresh_client.connection.local_address.address, username: username
    fresh_client.connection.send(ServerHandshakePacket.new)
    fresh_client.auth_channel.send(username)
  end

  def handle_client(client : Client) : Nil
    bytes = Bytes.new(Packet::MaxSize)

    until client.connection.closed?
      bytes_read, _ = client.connection.receive(bytes)
      break if bytes_read.zero? # Connection was closed
      packet = Packet.from_bytes(bytes[0...bytes_read].dup)
      client.packet_channel.send(packet)
    end
  end

  def handle_packet(client : Client, packet : Packet) : Nil
    Log.trace { packet }
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

  def handle_command(command : String) : Nil
    case command
    when "hello"
      Log.info { "world!" }
    when "stop"
      self.stop
    when "list"
      Log.info { @clients }
    else
      Log.error { "Unknown command! - #{command}" }
    end
  end

  def start : Nil
    self.set_terminal_mode
    Log.info { "Server started!" }
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
      when username = fresh_client.auth_channel.receive
        if username
          client = Client.new(fresh_client.connection, username)
          @clients << client
        end
        next true
      else
        next false
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
        self.handle_command(command) if command
      end
    else
    end

    @tick += 1
  end

  def stop : NoReturn
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

begin
  server = Woozy::Server.new(host, port)
  server.start
rescue ex
  Log.fatal(exception: ex) { "" }
  if server
    server.stop
  end
end
