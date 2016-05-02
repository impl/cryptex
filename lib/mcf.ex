defmodule ExCrypto.Mcf do

  alias ExCrypto.Mcf.Encoder

  def encode!(kdf) do
    {:ok, string} = encode(kdf)
    string
  end
  def encode(kdf) do
    case Encoder.encode(kdf) do
      {:ok, name, data} -> {:ok, format(name, data)}
      {:error, _} = e -> e
    end
  end

  defp format(name, data), do: "$#{name}$#{data}"

  defprotocol Encoder do

    def encode(kdf)

  end

end
