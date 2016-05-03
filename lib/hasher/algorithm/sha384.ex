defmodule ExCrypto.Hasher.Algorithm.Sha384 do

  @block_size_bits 1024
  @digest_size_bits 384

  use ExCrypto.Hasher.BuiltinAlgorithm, algorithm: :sha384,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
