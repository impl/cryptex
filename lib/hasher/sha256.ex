defmodule ExCrypto.Hasher.Sha256 do

  @block_size_bits 512
  @digest_size_bits 256

  use ExCrypto.Hasher.Builtin, algorithm: :sha256,
    block_size: div(@block_size_bits, 8),
    digest_size: div(@digest_size_bits, 8)

end
