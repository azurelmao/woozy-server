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

  def set_terminal_mode
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

  def key_loop(channel : Channel(Char | Key))
    loop do
      char = STDIN.read_char

      case char
      when nil # STDIN was closed
        exit
      when '\u{3}' # Ctrl+C
        puts "^C"
        exit
      when '\u{4}' # Ctrl+D
        puts
        exit
      when '\e'
        case char2 = STDIN.read_char
        when nil
          exit
        when '['
          case char3 = STDIN.read_char
          when nil
            exit
          when 'A'
            channel.send Key::Up
          when 'B'
            channel.send Key::Down
          when 'C'
            channel.send Key::Right
          when 'D'
            channel.send Key::Left
          when '3'
            case char4 = STDIN.read_char
            when nil
              exit
            when '~'
              channel.send Key::Delete
            end
          end
        end
      when '\n'
        channel.send Key::Enter
      when '\u{7f}'
        channel.send Key::Backspace
      else
        channel.send char
      end
    end
  end

  def handle_command(command : String)
    case command
    when "stop"
      stop
    when "hello"
      Log.info { "world!" }
    else
      Log.error { "Unknown command!" }
    end
  end
end
