require "./registry"

abstract struct Woozy::BlockImpl
  Air = AirBlockImpl.new

  Registry::BlockImpl.register Air, as: Id.of("air")
end
