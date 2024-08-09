require "./block_impl"

# Storage unit which represents a voxel's data
struct Woozy::Block
  @impl : BlockImpl
  @state : Int32

  def initialize(@impl, @state = 0)
  end

  def []=(offset : Int32, value : Int32) : Nil
    @state |= (value << offset)
  end

  def [](offset : Int32, width : Int32) : Int32
    (@state >> offset) & width
  end
end
