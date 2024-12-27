module Woozy
  class BlockRegistry
    def initialize
      @current_index = 0_u32
      @index_to_impl = Array(BlockImpl).new
      @index_to_name = Array(String).new
      @name_to_index = Hash(String, BlockIdx).new
    end

    def register(name : String, impl : BlockImpl) : BlockIdx
      index = @current_index
      @index_to_impl << impl
      @index_to_name << name
      @name_to_index[name] = index
      @current_index += 1_u32
      index
    end

    def impl_of(index : BlockIdx) : BlockImpl
      @index_to_impl[index]
    end

    def name_of(index : BlockIdx) : String
      @index_to_name[index]
    end

    def index_of(name : String) : BlockIdx
      @name_to_index[name]
    end
  end

  class Blocks
    getter registry : BlockRegistry
    getter air : BlockIdx
    getter stone : BlockIdx
    getter grass : BlockIdx

    def initialize
      @registry = BlockRegistry.new

      @air = @registry.register "air", AirBlockImpl.new
      @stone = @registry.register "stone", StoneBlockImpl.new
      @grass = @registry.register "grass", GrassBlockImpl.new
    end

    delegate register, impl_of, name_of, index_of, to: @registry
  end

  abstract struct BlockImpl
  end

  module NonSolidBlockImpl
  end

  module SolidBlockImpl
  end

  struct AirBlockImpl < BlockImpl
    include NonSolidBlockImpl
  end

  struct StoneBlockImpl < BlockImpl
    include SolidBlockImpl
  end

  struct GrassBlockImpl < BlockImpl
    include SolidBlockImpl
  end
end
