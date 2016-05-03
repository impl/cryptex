defmodule ExCrypto.Mac.Hmac do

  alias ExCrypto.Hasher
  alias ExCrypto.Mac.Hmac

  use Bitwise

  defstruct hasher: nil
  @typedoc """
  An opaque instance of this module that can be used to predefine a hashing algorithm to use for key generation.
  """
  @opaque t :: %Hmac{}

  @spec new(Hasher.t | Hasher.algorithm) :: Hmac.t
  def new(%Hasher{} = hasher), do: %Hmac{hasher: hasher}
  def new(module), do: Hasher.new(module) |> new

  @spec generate(Hmac.t | Hasher.t | Hasher.algorithm, binary, Hasher.State.digestable) :: binary
  def generate(%Hmac{hasher: hasher}, key, data) do
    hmac_inner(hasher, Hasher.block_size(hasher), key, data)
  end
  def generate(module, key, data), do: generate(new(module), key, data)

  @spec hasher(Hmac.t) :: Hasher.t
  def hasher(%Hmac{hasher: hasher}), do: hasher

  @spec digest_size(Hmac.t) :: integer
  def digest_size(%Hmac{hasher: hasher}), do: Hasher.digest_size(hasher)

  defp hmac_inner(hasher, block_size, key, data) when byte_size(key) > block_size do
    hmac_inner(hasher, block_size, Hasher.digest(hasher, key), data)
  end
  defp hmac_inner(hasher, block_size, key, data) do
    key_pad_bits = (block_size - byte_size(key)) * 8
    key_prime = key <> <<0 :: size(key_pad_bits)>>

    o_pad = :crypto.exor(key_prime, String.duplicate(<<0x5c>>, block_size))
    i_pad = :crypto.exor(key_prime, String.duplicate(<<0x36>>, block_size))

    inner = Hasher.digest(hasher, [i_pad, data])
    Hasher.digest(hasher, [o_pad, inner])
  end

end
