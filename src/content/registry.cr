require "woozy/registry"

struct Woozy::Registry
  BlockImpl = Registry(Woozy::BlockImpl).new
end
