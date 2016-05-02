defmodule ExCrypto.Hasher.Md4 do

  @block_size_bits 512
  @digest_size_bits 128

  use ExCrypto.Hasher.Builtin, algorithm: :md4,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
