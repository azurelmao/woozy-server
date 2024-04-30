module Woozy
  alias BlockIdx = UInt32

  # Base for a functional implementation of a block
  abstract struct BlockImpl
    property idx : BlockIdx?
  end

  struct AirBlockImpl < BlockImpl
  end
end
