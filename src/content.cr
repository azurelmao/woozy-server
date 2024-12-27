require "./block_impl"

class Woozy::Content
  getter blocks : Blocks

  def initialize
    @blocks = Blocks.new
  end
end
