# IETF RFC 2989 PBKDF2 algorithm.

# Based on David Whitlock's implementation in Comeonin.
# https://github.com/elixircnx/comeonin/blob/88af670ccd4e6615ff8ddf987aa47ed182b29a08/lib/comeonin/pbkdf2.ex
#
# Released under a BSD-style license. For more information, see the included LICENSE file.

defmodule ExCrypto.Kdf.Pbkdf2 do

  alias ExCrypto.Kdf.Pbkdf2
  alias ExCrypto.Kdf.Pbkdf2.Prf

  @default_rounds 160_000
  @default_salt_size 16

  defstruct prf: nil, digest: nil, salt: nil, rounds: nil

  def new!(prf, secret, salt \\ nil, opts \\ []) do
    case new(prf, secret, salt, opts) do
      {:ok, result} -> result
      {:error, error} -> raise error
    end
  end

  def new(prf, secret, salt \\ nil, opts \\ [])
  def new(prf, secret, nil, opts) do
    case random_salt(Keyword.get(opts, :salt_size, @default_salt_size)) do
      {:ok, salt} -> new(prf, secret, salt, opts)
      {:error, _} = e -> e
    end
  end
  def new(prf, secret, salt, opts) do
    rounds = Keyword.get(opts, :rounds, @default_rounds)
    digest_size = Prf.digest_size(prf)
    hash_size = Keyword.get(opts, :hash_size, digest_size)

    case rem(hash_size, digest_size) do
      0 -> hash_inner([], prf, secret, salt, rounds, hash_size, div(hash_size, digest_size), 1)
      _ -> {:error, ArgumentError.exception(message: "Hash size must be a multiple of pseudo-random function's output size")}
    end
  end

  def digest(%Pbkdf2{digest: digest}), do: digest

  def salt(%Pbkdf2{salt: salt}), do: salt

  def rounds(%Pbkdf2{rounds: rounds}), do: rounds

  defp hash_inner(_acc, _prf, _secret, _salt, rounds, _hash_size, _remaining, _block_index) when rounds <= 0 do
    {:error, ArgumentError.exception(message: "Number of rounds must be greater than 0")}
  end
  defp hash_inner(_acc, _prf, _secret, _salt, _rounds, hash_size, _remaining, _block_index) when hash_size <= 0 do
    {:error, ArgumentError.exception(message: "Hash size must be greater than 0")}
  end
  defp hash_inner(acc, prf, _secret, salt, rounds, _hash_size, 0, _block_index) do
    {:ok, %Pbkdf2{prf: prf, digest: acc |> Enum.reverse |> IO.iodata_to_binary, salt: salt, rounds: rounds}}
  end
  defp hash_inner(acc, prf, secret, salt, rounds, hash_size, remaining, block_index) do
    result = case Prf.apply(prf, secret, <<salt :: binary, block_index :: big-integer-size(32)>>) do
      {:ok, result} -> hash_iterate(prf, secret, result, rounds - 1, result)
      {:error, _} = e -> e
    end

    case result do
      {:ok, block} -> hash_inner([block | acc], prf, secret, salt, rounds, hash_size, remaining - 1, block_index + 1)
      {:error, _} = e -> e
    end
  end

  defp hash_iterate(_prf, _secret, _prev, 0, acc), do: {:ok, acc}
  defp hash_iterate(prf, secret, prev, rounds, acc) do
    case Prf.apply(prf, secret, prev) do
      {:ok, result} -> hash_iterate(prf, secret, result, rounds - 1, :crypto.exor(result, acc))
      {:error, _} = e -> e
    end
  end

  defp random_salt(salt_size) when salt_size < 16 do
    {:error, ArgumentError.exception(message: "Salt size must be at least 16 bytes")}
  end
  defp random_salt(salt_size) do
    {:ok, :crypto.strong_rand_bytes(salt_size)}
  end

  defprotocol Prf do

    def apply(f, secret, salt)
    def digest_size(f)
    def name(f)

  end

  defmodule Mcf.Alphabet do

    use ExCrypto.Utils.Base64, alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./', padding: false

  end

end

defimpl ExCrypto.Kdf.Pbkdf2.Prf, for: ExCrypto.Mac.Hmac do

  alias ExCrypto.Hasher
  alias ExCrypto.Mac.Hmac

  defdelegate apply(f, secret, salt), to: Hmac, as: :hmac
  defdelegate digest_size(f), to: Hmac
  def name(f), do: Hmac.hasher(f) |> Hasher.name

end

defimpl ExCrypto.Mcf.Encoder, for: ExCrypto.Kdf.Pbkdf2 do

  alias ExCrypto.Kdf.Pbkdf2

  def encode(%Pbkdf2{prf: %ExCrypto.Mac.Hmac{} = prf, digest: digest, salt: salt, rounds: rounds}) do
    {:ok, "pbkdf2-#{Pbkdf2.Prf.name(prf)}", "#{rounds}$#{Pbkdf2.Mcf.Alphabet.encode(salt)}$#{Pbkdf2.Mcf.Alphabet.encode(digest)}"}
  end
  def encode(_) do
    {:error, ArgumentError.exception(message: "No representation for this pseudo-random function is available for PBKDF2")}
  end

end
