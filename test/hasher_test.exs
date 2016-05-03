defmodule ExCrypto.HasherTest do

  use ExUnit.Case
  alias ExCrypto.Hasher

  @provided [:md4, :md5, :ripemd160, :sha1, :sha224, :sha256, :sha384, :sha512, :whirlpool]

  test "atoms are resolved to modules" do
    assert Hasher.new(:sha256) == Hasher.new(ExCrypto.Hasher.Algorithm.Sha256)
  end

  test "digest sizes are correct" do
    @provided |> Enum.map(fn algo ->
      assert byte_size(Hasher.digest(algo, "test")) == Hasher.new(algo) |> Hasher.digest_size
    end)
  end

  test "hasher implementations are collectable" do
    @provided |> Enum.map(fn algo ->
      assert ["te", "st"] |> Enum.into(Hasher.new(algo)) == Hasher.digest(algo, "test")
    end)
  end

  test "digest with data is equivalent to new followed by update followed by digest" do
    @provided |> Enum.map(fn algo ->
      assert Hasher.new_state(algo) |> Hasher.State.update("test") |> Hasher.State.digest == Hasher.digest(algo, "test")
    end)
  end

  test "all algorithms specify a block size" do
    @provided |> Enum.map(fn algo ->
      assert Hasher.new(algo) |> Hasher.block_size > 0
    end)
  end

  test "all algorithms specify a name" do
    @provided |> Enum.map(fn algo ->
      assert Hasher.new(algo) |> Hasher.name
    end)
  end

end
