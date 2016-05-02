defmodule ExCrypto.Hasher.Builtin do

  defmacro __using__(algorithm: algorithm, block_size: block_size, digest_size: digest_size) do
    quote location: :keep do

      @behaviour ExCrypto.Hasher

      def new(_opts), do: :crypto.hash_init(unquote(algorithm))
      defdelegate update(context, data), to: :crypto, as: :hash_update
      defdelegate digest(context), to: :crypto, as: :hash_final

      def block_size, do: unquote(block_size)
      def digest_size, do: unquote(digest_size)

      def name, do: Atom.to_string(unquote(algorithm))

    end
  end

end
