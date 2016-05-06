defmodule Cryptex.Utils.ConstantTime do

  use Bitwise

  @spec binaries_equal?(binary, binary) :: boolean
  def binaries_equal?(expected, test) when byte_size(expected) == byte_size(test) do
    :crypto.exor(expected, test) |> expect_zeros
  end
  def binaries_equal?(_, _), do: false

  defp expect_zeros(data) do
    expect_zeros(data, 0)
  end

  defp expect_zeros(<<>>, acc), do: acc == 0
  defp expect_zeros(<<b, rest :: binary>>, acc) do
    expect_zeros(rest, acc ||| b)
  end

end
