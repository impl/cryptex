# IETF RFC 2989 PBKDF2 algorithm.

# Based on David Whitlock's implementation in Comeonin.
# https://github.com/elixircnx/comeonin/blob/88af670ccd4e6615ff8ddf987aa47ed182b29a08/lib/comeonin/pbkdf2.ex
#
# Released under a BSD-style license. For more information, see the included LICENSE file.

defmodule Cryptex.Kdf.Pbkdf2 do

  alias Cryptex.Kdf.Pbkdf2
  alias Cryptex.Kdf.Pbkdf2.Prf
  alias Cryptex.Kdf.Pbkdf2.Result

  @default_rounds 160_000
  @default_salt_size 16

  defstruct prf: nil, opts: []
  @opaque t :: %Pbkdf2{}

  @spec new(Prf.t, Keyword.t) :: t
  def new(prf, opts \\ []) do
    %Pbkdf2{prf: prf, opts: opts}
  end

  @spec from_computed(Prf.t, integer, binary, binary) :: Result.t
  def from_computed(prf, rounds, salt, secret) do
    Result.new(prf, rounds, salt, secret)
  end

  @spec derive(t | Prf.t, any, binary | nil, Keyword.t) :: Result.t
  def derive(pbkdf2_or_prf, secret, salt \\ nil, opts \\ [])
  def derive(%Pbkdf2{prf: prf, opts: base_opts}, secret, salt, opts) do
    derive(prf, secret, salt, Keyword.merge(base_opts, opts))
  end
  def derive(prf, secret, nil, opts) do
    salt = random_salt(Keyword.get(opts, :salt_size, @default_salt_size))
    derive(prf, secret, salt, opts)
  end
  def derive(prf, secret, salt, opts) do
    rounds = Keyword.get(opts, :rounds, @default_rounds)
    digest_size = Prf.digest_size(prf)
    hash_size = Keyword.get(opts, :hash_size, digest_size)

    case rem(hash_size, digest_size) do
      0 -> hash_inner([], prf, secret, salt, rounds, hash_size, div(hash_size, digest_size), 1)
      _ -> raise ArgumentError, "Hash size must be a multiple of pseudo-random function's output size"
    end
  end

  defp hash_inner(_acc, _prf, _secret, _salt, rounds, _hash_size, _remaining, _block_index) when rounds <= 0 do
    raise ArgumentError, "Number of rounds must be greater than 0"
  end
  defp hash_inner(_acc, _prf, _secret, _salt, _rounds, hash_size, _remaining, _block_index) when hash_size <= 0 do
    raise ArgumentError, "Hash size must be greater than 0"
  end
  defp hash_inner(acc, prf, _secret, salt, rounds, _hash_size, 0, _block_index) do
    Result.new(prf, rounds, salt, acc |> Enum.reverse |> IO.iodata_to_binary)
  end
  defp hash_inner(acc, prf, secret, salt, rounds, hash_size, remaining, block_index) do
    initial = Prf.apply(prf, secret, <<salt :: binary, block_index :: big-integer-size(32)>>)
    block = hash_iterate(prf, secret, initial, rounds - 1, initial)
    hash_inner([block | acc], prf, secret, salt, rounds, hash_size, remaining - 1, block_index + 1)
  end

  defp hash_iterate(_prf, _secret, _prev, 0, acc), do: acc
  defp hash_iterate(prf, secret, prev, rounds, acc) do
    result = Prf.apply(prf, secret, prev)
    hash_iterate(prf, secret, result, rounds - 1, :crypto.exor(result, acc))
  end

  defp random_salt(salt_size) when salt_size < 16 do
    raise ArgumentError, "Salt size must be at least 16 bytes"
  end
  defp random_salt(salt_size) do
    :crypto.strong_rand_bytes(salt_size)
  end

end
