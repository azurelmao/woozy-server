# Base for a 3D integer point in space
abstract struct Woozy::Pos3
  @vec : StaticArray(Int32, 3)

  delegate to_unsafe, to: @vec
  def_hash x, y, z

  def initialize(x : Int32, y : Int32, z : Int32)
    @vec = StaticArray[x, y, z]
  end

  def x : Int32
    @vec[0]
  end

  def y : Int32
    @vec[1]
  end

  def z : Int32
    @vec[2]
  end

  def - : self
    self.class.new(-x, -y, -z)
  end

  {% for operator in ["+", "-", "*", "**", "/", "//", "%"] %}
    def {{operator.id}}(other : self) : self
      self.class.new(
        x {{operator.id}} other.x,
        y {{operator.id}} other.y,
        z {{operator.id}} other.z
      )
    end
  {% end %}

  {% for operator in ["+", "-", "*", "**", "/", "//", "%"] %}
    def {{operator.id}}(value : Int32) : self
      self.class.new(
        x {{operator.id}} value,
        y {{operator.id}} value,
        z {{operator.id}} value
      )
    end
  {% end %}

  def to(other : self, & : self ->) : Nil
    x.to other.x do |x|
      y.to other.y do |y|
        z.to other.z do |z|
          yield self.class.new(x, y, z)
        end
      end
    end
  end
end

struct Int
  {% for operator in ["+", "-", "*", "**", "/", "//", "%"] %}
    def {{operator.id}}(pos3 : Woozy::Pos3) : Woozy::Pos3
      pos3.class.new(
        self {{operator.id}} pos3.x,
        self {{operator.id}} pos3.y,
        self {{operator.id}} pos3.z
      )
    end
  {% end %}
end
