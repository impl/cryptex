defmodule ExCrypto.Utils.Base64 do

  use Bitwise

  defmacro __using__(opts) do
    alphabet = Keyword.get(opts, :alphabet)
    default_padding = Keyword.get(opts, :padding, true)

    quote location: :keep do

      unquote do
        for {encoding, value} <- Enum.with_index(alphabet) do
          quote do
            defp encode_char(unquote(value)), do: unquote(encoding)
            defp decode_char(unquote(encoding)), do: unquote(value)
          end
        end
      end

      defp decode_char(c) do
        raise ArgumentError, "Non-alphabet digit found: #{inspect <<c>>, binaries: :as_strings} (byte #{c})"
      end

      def encode(data, opts \\ []) do
        pad? = Keyword.get(opts, :padding, unquote(default_padding))
        do_encode(data, pad?)
      end

      def decode(data, opts \\ []) do
        pad? = Keyword.get(opts, :padding, unquote(default_padding))
        do_decode(data, pad?)
      end

      defp maybe_pad(subject, false, _, _), do: subject
      defp maybe_pad(subject, _, group_size, pad) do
        case rem(byte_size(subject), group_size) do
          0 -> subject
          x -> subject <> String.duplicate(pad, group_size - x)
        end
      end

      defp do_encode(<<>>, _), do: <<>>
      defp do_encode(data, pad?) do
        split =  3 * div(byte_size(data), 3)
        <<main :: size(split)-binary, rest :: binary>> = data
        main = for <<c :: 6 <- main>>, into: <<>>, do: <<encode_char(c) :: 8>>
        tail = case rest do
          <<c1 :: 6, c2 :: 6, c3 :: 4>> ->
            <<encode_char(c1) :: 8, encode_char(c2) :: 8, encode_char(bsl(c3, 2)) :: 8>>
          <<c1 :: 6, c2 :: 2>> ->
            <<encode_char(c1) :: 8, encode_char(bsl(c2, 4)) :: 8>>
          <<>> -> <<>>
        end
        main <> maybe_pad(tail, pad?, 4, "=")
      end

	  defp do_decode(<<>>, _), do: <<>>
	  defp do_decode(string, false) do
		maybe_pad(string, true, 4, "=") |> do_decode(true)
	  end
	  defp do_decode(string, _pad?) when rem(byte_size(string), 4) == 0 do
		split = byte_size(string) - 4
		<<main :: size(split)-binary, rest :: binary>> = string
		main = for <<c :: 8 <- main>>, into: <<>>, do: <<decode_char(c) :: 6>>
		tail = case rest do
		  <<c1 :: 8, c2 :: 8, ?=, ?=>> ->
			<<decode_char(c1) :: 6, bsr(decode_char(c2), 4) :: 2>>
		  <<c1 :: 8, c2 :: 8, c3 :: 8, ?=>> ->
			<<decode_char(c1) :: 6, decode_char(c2) :: 6, bsr(decode_char(c3), 2) :: 4>>
		  <<c1 :: 8, c2 :: 8, c3 :: 8, c4 :: 8>> ->
			<<decode_char(c1) :: 6, decode_char(c2) :: 6, decode_char(c3) :: 6, decode_char(c4) :: 6>>
		  <<>> -> <<>>
		end
		main <> tail
	  end
	  defp do_decode(_, _) do
        raise ArgumentError, "Invalid padding"
	  end

    end
  end

end
