require "bit_array"
require "../util/chunk_pos"
require "../content/block_impl"
require "./block"

module Woozy
  alias Light = UInt8

  class Chunk
    Size    = 32
    BitMask = 31
    BitSize =  5

    getter position : ChunkPos
    @block_palette : Hash(UInt16, Block)
    @block_ids : Slice(UInt16)
    @light : Slice(Light)

    def initialize(*, at @position)
      @block_palette = Hash(UInt16, Block).new
      @block_palette[0] = Block.new(BlockImpl::Air)
      @block_ids = Slice(UInt16).new(Size ** 3, 0)
      @light = Slice(Light).new(Size ** 3, 0)
    end

    def set_light(position : LocalPos, light : Light) : Nil
      raise "Position out of bounds" unless position.valid?

      @light[position.index] = light
    end

    def get_light(position : LocalPos) : Light
      raise "Position out of bounds" unless position.valid?

      @light[position.index]
    end

    def set_block(position : LocalPos, block : Block) : Nil
      raise "Position out of bounds" unless position.valid?

      if key = @block_palette.key_for? block
        @block_ids[position.index] = key
      else
        key = @block_palette.size.to_u16
        @block_palette[key] = block
        @block_ids[position.index] = key
      end
    end

    def get_block(position : LocalPos) : Block
      raise "Position out of bounds" unless position.valid?

      key = @block_ids[position.index]
      block = @block_palette[key]
    end
  end
end
