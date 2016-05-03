defmodule Cryptex.Hasher.Algorithm.Sha224 do

  @block_size_bits 512
  @digest_size_bits 224

  use Cryptex.Hasher.BuiltinAlgorithm, algorithm: :sha224,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
