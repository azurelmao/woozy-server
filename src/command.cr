struct Woozy::Server
  enum Key
    Enter
    Backspace
    Delete
    Up
    Down
    Right
    Left
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

  alias Command = String

  def key_loop(channel : Channel(Command)) : Nil
    self.set_terminal_mode

    loop do
      char = STDIN.read_char

      case char
      when nil # STDIN was closed
        self.stop
      when '\u{3}' # Ctrl+C
        puts "^C"
        self.stop
      when '\u{4}' # Ctrl+D
        puts
        self.stop
      when '\e'
        case char2 = STDIN.read_char
        when nil
          self.stop
        when '['
          case char3 = STDIN.read_char
          when nil
            self.stop
          when 'A'
            self.handle_key(channel, Key::Up)
          when 'B'
            self.handle_key(channel, Key::Down)
          when 'C'
            self.handle_key(channel, Key::Right)
          when 'D'
            self.handle_key(channel, Key::Left)
          when '3'
            case char4 = STDIN.read_char
            when nil
              self.stop
            when '~'
              self.handle_key(channel, Key::Delete)
            end
          end
        end
      when '\n'
        self.handle_key(channel, Key::Enter)
      when '\u{7f}'
        self.handle_key(channel, Key::Backspace)
      else
        self.handle_key(channel, char)
      end
    end
  end

  def handle_key(channel : Channel(Command), key : Char | Key) : Nil
    case key
    when Char
      @command_history.write_at_cursor(key)
    when .enter?
      channel.send @command_history.send
    when .backspace?
      @command_history.delete_prev_char
    when .delete?
      @command_history.delete_current_char
    when .up?
      @command_history.move_to_prev_record
    when .down?
      @command_history.move_to_next_record
    when .right?
      @command_history.move_cursor_right
    when .left?
      @command_history.move_cursor_left
    end
  end

  def handle_command(command : String) : Nil
    case command
    when "stop"
      stop
    when "hello"
      Log.info { "world!" }
    else
      Log.error { "Unknown command!" }
    end
  end

  def clear_line : Nil
    print "\e[2K\r"
  end

  def print_current_line : Nil
    print "> #{@command_history.current_record.join}\r\e[#{2 + @command_history.cursor_index}C"
  end
end
