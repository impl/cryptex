defmodule ExCrypto.Hasher.Ripemd160 do

  @block_size_bits 512
  @digest_size_bits 160

  use ExCrypto.Hasher.Builtin, algorithm: :ripemd160,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
