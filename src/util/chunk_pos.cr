require "./position"

# Represents an absolute position of a chunk, relative to the center of the world
struct Woozy::ChunkPos < Woozy::Pos3
  def to_global_pos
    GlobalPos.new(
      x << Chunk::BitSize,
      y << Chunk::BitSize,
      z << Chunk::BitSize
    )
  end

  def to_global_borders : {GlobalPos, GlobalPos}
    from = to_global_pos
    to = from + Chunk::BitMask
    {from, to}
  end
end
