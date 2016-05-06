defmodule Cryptex.Kdf.Pbkdf2.ResultTest do

  use ExUnit.Case
  alias Cryptex.Kdf.Pbkdf2.Result
  alias Cryptex.Mac.Hmac

  test "functions return values from computed key" do
    prf = Hmac.new(:sha512)

    result = Result.new(prf, 10_000, "salt", "digest")

    assert Result.prf(result) == prf
    assert Result.rounds(result) == 10_000
    assert Result.salt(result) == "salt"
    assert Result.digest(result) == "digest"
  end

end
