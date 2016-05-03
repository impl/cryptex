defmodule ExCrypto.Hasher.BuiltinAlgorithm do

  defmacro __using__(algorithm: algorithm, block_size: block_size, digest_size: digest_size) do
    quote location: :keep do

      @behaviour ExCrypto.Hasher.Algorithm

      @type t :: any

      @spec new(Keyword.t) :: t
      def new(_opts), do: :crypto.hash_init(unquote(algorithm))

      @spec update(t, binary) :: t
      defdelegate update(context, data), to: :crypto, as: :hash_update

      @spec digest(t) :: binary
      defdelegate digest(context), to: :crypto, as: :hash_final

      @spec block_size() :: integer
      def block_size, do: unquote(block_size)

      @spec digest_size() :: integer
      def digest_size, do: unquote(digest_size)

      @spec name() :: String.t
      def name, do: Atom.to_string(unquote(algorithm))

    end
  end

end
