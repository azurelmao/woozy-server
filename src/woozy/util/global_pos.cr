require "./position"

# Represents an absolute position of a block, relative to the center of the world
struct Woozy::GlobalPos < Woozy::Pos3
  def to_chunk_pos : ChunkPos
    ChunkPos.new(
      x >> Chunk::BitSize,
      y >> Chunk::BitSize,
      z >> Chunk::BitSize
    )
  end

  def to_local_pos : LocalPos
    LocalPos.new(
      x & Chunk::BitMask,
      y & Chunk::BitMask,
      z & Chunk::BitMask
    )
  end

  {% for operator in ["+", "-", "*", "**", "/", "//", "%"] %}
    def {{operator.id}}(other : LocalPos) : self
      self.class.new(
        x {{operator.id}} other.x,
        y {{operator.id}} other.y,
        z {{operator.id}} other.z
      )
    end
  {% end %}
end
