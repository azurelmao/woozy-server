require "woozy/chunk"

struct Woozy::World
  @chunks = Hash(ChunkPos, Chunk).new

  # Returns the chunk at `position`, or nil if not found.
  def get_chunk(position : ChunkPos) : Chunk?
    @chunks[position]?
  end

  # Sets the chunk at the `chunk`'s position.
  def set_chunk(chunk : Chunk) : Nil
    @chunks[chunk.position] = chunk
  end

  # Iterates through each chunk in the world.
  def each_chunk(& : Chunk ->)
    @chunks.each_value do |chunk|
      yield chunk
    end
  end

  # Casts a ray from `origin` in the direction of `direction`,
  # and returns the first block it hit with `#interactable?` behavior or nil if not found, its position, and the side or nil.
  # Is limited to a maximum of 120 iterations.
  def raycast(origin : Vec3, direction : Vec3) : {Block?, GlobalPos, Side?}
    position = origin.floor

    step = Vec3.new(direction.x.sign.to_f32, direction.y.sign.to_f32, direction.z.sign.to_f32)
    delta_distance = (Vec3.new(direction.magnitude) / direction).abs
    side_distance = (step * (position - origin) + (step * 0.5_f32) + 0.5_f32) * delta_distance

    mask = {false, false, false}

    120.times do
      block_pos = position.to_pos3.to_global_pos
      block = get_block(block_pos)
      if block && block.behavior.interactable?
        side = if mask[0]
                 if step.x > 0
                   Side::West
                 elsif step.x < 0
                   Side::East
                 end
               elsif mask[1]
                 if step.y > 0
                   Side::Down
                 elsif step.y < 0
                   Side::Up
                 end
               elsif mask[2]
                 if step.z > 0
                   Side::North
                 elsif step.z < 0
                   Side::South
                 end
               end

        return {block, block_pos, side}
      end

      if side_distance.x < side_distance.y
        if side_distance.x < side_distance.z
          side_distance.x += delta_distance.x
          position.x += step.x
          mask = {true, false, false}
        else
          side_distance.z += delta_distance.z
          position.z += step.z
          mask = {false, false, true}
        end
      else
        if side_distance.y < side_distance.z
          side_distance.y += delta_distance.y
          position.y += step.y
          mask = {false, true, false}
        else
          side_distance.z += delta_distance.z
          position.z += step.z
          mask = {false, false, true}
        end
      end
    end

    {nil, position.to_pos3.to_global_pos, nil}
  end

  # Sets the light at `position`, or does nothing if not found.
  def set_light(position : GlobalPos, light : Light) : Nil
    chunk = get_chunk(position.to_chunk_pos)
    return unless chunk

    chunk.set_light(position.to_local_pos, light)
  end

  # Returns the light at `position`, or nil if not found.
  def get_light(position : GlobalPos) : Light?
    chunk = get_chunk(position.to_chunk_pos)
    chunk.get_light(position.to_local_pos) if chunk
  end

  # Sets the block at `position`, or does nothing if out of bounds.
  def set_block(position : GlobalPos, block : Block) : Nil
    chunk = get_chunk(position.to_chunk_pos)
    return unless chunk

    local_pos = position.to_local_pos
    chunk.set_block(local_pos, block)
    chunk.set_changed(local_pos.to_octet_pos, true)
  end

  # Returns the block at `position`, or nil if not found.
  def get_block(position : GlobalPos) : Block?
    chunk = get_chunk(position.to_chunk_pos)
    chunk.get_block(position.to_local_pos) if chunk
  end

  # Optimized version of `#set_block` for bulk setting.
  # Iterates through a volume from position `from` to position `to`, and sets a block or does nothing if out of bounds.
  def bulk_set_block(from pos1 : GlobalPos, to pos2 : GlobalPos, block : Block) : Nil
    chunk_pos1 = pos1.to_chunk_pos
    chunk_pos2 = pos2.to_chunk_pos

    chunk_pos1.to chunk_pos2 do |chunk_pos|
      chunk = get_chunk(chunk_pos)
      next unless chunk

      chunk_border1, chunk_border2 = chunk_pos.to_global_borders

      local_pos1 = pos1.clamp(chunk_border1, chunk_border2).to_local_pos
      local_pos2 = pos2.clamp(chunk_border1, chunk_border2).to_local_pos

      local_pos1.to_octet_pos.to local_pos2.to_octet_pos do |octet_pos|
        chunk.set_changed(octet_pos, true)
      end

      local_pos1.to local_pos2 do |local_pos|
        chunk.set_block(local_pos, block)
      end
    end
  end

  # Optimized version of `#get_block` for bulk getting.
  # Iterates through a volume from position `from` to position `to`, and yields a block or nil if not found, and its position.
  def bulk_get_block(from pos1 : GlobalPos, to pos2 : GlobalPos, & : (Block?, GlobalPos) ->) : Nil
    chunk_pos1 = pos1.to_chunk_pos
    chunk_pos2 = pos2.to_chunk_pos

    chunk_pos1.to chunk_pos2 do |chunk_pos|
      chunk = get_chunk(chunk_pos)

      chunk_border1, chunk_border2 = chunk_pos.to_global_borders

      local_pos1 = pos1.clamp(chunk_border1, chunk_border2).to_local_pos
      local_pos2 = pos2.clamp(chunk_border1, chunk_border2).to_local_pos

      local_pos1.to local_pos2 do |local_pos|
        if chunk
          yield chunk.get_block(local_pos), chunk_pos.to_global_pos + local_pos
        else
          yield nil, chunk_pos.to_global_pos + local_pos
        end
      end
    end
  end
end
