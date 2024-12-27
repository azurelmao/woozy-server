require "./server_actor"

module Crystal
  def self.main_user_code(argc : Int32, argv : UInt8**)
    begin
      previous_def
    rescue ex
      Log.fatal(exception: ex) { "" }
    end
  end
end

begin
  raise "Mismatched number of arguments" if ARGV.size.odd?

  host = "localhost"
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

  server = Woozy::ServerActor.new(host, port)
  server.start
rescue ex
  Log.fatal(exception: ex) { "" }
  if server
    server.stop
  end
end
