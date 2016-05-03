defmodule Cryptex.Hasher.Algorithm.Sha1 do

  @block_size_bits 512
  @digest_size_bits 160

  use Cryptex.Hasher.BuiltinAlgorithm, algorithm: :sha,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
