struct Woozy::Client
  @socket : TCPSocket
  getter username : String

  delegate close, send, local_address, to: @socket

  def initialize(@socket, @username)
  end
end
