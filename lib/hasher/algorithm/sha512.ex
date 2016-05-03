defmodule ExCrypto.Hasher.Algorithm.Sha512 do

  @block_size_bits 1024
  @digest_size_bits 512

  use ExCrypto.Hasher.BuiltinAlgorithm, algorithm: :sha512,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
