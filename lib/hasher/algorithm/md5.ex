defmodule Cryptex.Hasher.Algorithm.Md5 do

  @block_size_bits 512
  @digest_size_bits 128

  use Cryptex.Hasher.BuiltinAlgorithm, algorithm: :md5,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
