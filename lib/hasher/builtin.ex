defmodule ExCrypto.Hasher.Builtin do

  defmacro __using__(algorithm: algorithm, block_size: block_size, digest_size: digest_size) do
    quote location: :keep do

      @behaviour ExCrypto.Hasher

      def new(_opts) do
        {:ok, :crypto.hash_init(unquote(algorithm))}
      end

      def update(context, data) do
        try do
          {:ok, :crypto.hash_update(context, data)}
        catch
          error -> {:error, error}
        end
      end

      def digest(context) do
        try do
          {:ok, :crypto.hash_final(context)}
        catch
          error -> {:error, error}
        end
      end

      def block_size, do: unquote(block_size)
      def digest_size, do: unquote(digest_size)

      def name, do: Atom.to_string(unquote(algorithm))

    end
  end

end
