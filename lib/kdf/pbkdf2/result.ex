defmodule ExCrypto.Kdf.Pbkdf2.Result do

  alias ExCrypto.Kdf.Pbkdf2.Result

  defstruct prf: nil, rounds: nil, salt: nil, digest: nil

  def new(prf, rounds, salt, digest) do
    %Result{prf: prf, rounds: rounds, salt: salt, digest: digest}
  end

  def prf(%Result{prf: prf}), do: prf
  def rounds(%Result{rounds: rounds}), do: rounds
  def salt(%Result{salt: salt}), do: salt
  def digest(%Result{digest: digest}), do: digest

  defmodule McfAlphabet do

    use ExCrypto.Utils.Base64, alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./', padding: false

  end

  defimpl ExCrypto.Mcf.Encoder do

    alias ExCrypto.Hasher
    alias ExCrypto.Kdf.Pbkdf2.Result
    alias ExCrypto.Mac.Hmac

    def encode(%Result{prf: %Hmac{} = prf, rounds: rounds, salt: salt, digest: digest}) do
      {"pbkdf2-#{Hmac.hasher(prf) |> Hasher.name}", "#{rounds}$#{Result.McfAlphabet.encode(salt)}$#{Result.McfAlphabet.encode(digest)}"}
    end
    def encode(_) do
      raise ArgumentError, "No representation for this pseudo-random function is available for PBKDF2"
    end

  end

end
