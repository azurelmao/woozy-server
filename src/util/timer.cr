struct Woozy::Timer
  @previous_time : Time? = nil
  @time_span : Time::Span

  def initialize(@time_span)
  end

  def run(&) : Nil
    if @previous_time.nil?
      @previous_time = Time.utc
      yield
      return
    end

    current_time = Time.utc
    elapsed_time = current_time - @previous_time.not_nil!

    if elapsed_time >= @time_span
      @previous_time = current_time

      (elapsed_time.total_nanoseconds // @time_span.total_nanoseconds).to_i.times do
        yield
      end
    end
  end
end
