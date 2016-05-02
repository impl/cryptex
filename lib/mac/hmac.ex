defmodule ExCrypto.Mac.Hmac do

  alias ExCrypto.Hasher
  alias ExCrypto.Mac.Hmac

  use Bitwise

  defstruct module: nil

  def new(module) do
    %Hmac{module: module}
  end

  def hmac(%Hmac{module: module}, key, data), do: hmac(module, key, data)
  def hmac(module, key, data) do
    hmac_inner(module, Hasher.block_size(module), key, data)
  end

  def hasher(%Hmac{module: module}), do: module
  def digest_size(%Hmac{module: module}), do: Hasher.digest_size(module)

  defp hmac_inner(module, block_size, key, data) when byte_size(key) > block_size do
    hmac_inner(module, block_size, Hasher.digest(module, key), data)
  end
  defp hmac_inner(module, block_size, key, data) do
    key_prime = :erlang.binary_to_list(key) ++ (1..(block_size - byte_size(key)) |> Enum.map(fn _ -> 0 end))
    o_pad = key_prime |> Enum.map(&(0x5c ^^^ &1))
    i_pad = key_prime |> Enum.map(&(0x36 ^^^ &1))

    inner = Hasher.digest(module, IO.iodata_to_binary([i_pad, data]))
    Hasher.digest(module, IO.iodata_to_binary([o_pad, inner]))
  end

end
