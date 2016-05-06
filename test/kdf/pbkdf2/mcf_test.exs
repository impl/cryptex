defmodule Cryptex.Kdf.Pbkdf2.McfTest do

  use ExUnit.Case
  alias Cryptex.Kdf.Pbkdf2.Result
  alias Cryptex.Mac.Hmac
  alias Cryptex.Mcf

  test "results can be encoded using modular crypt format" do
    prf = Hmac.new(:sha512)
    rounds = 100_000
    salt = "saltKEYbcTcXHCBxtjD"
    digest = <<
      172, 205, 205, 135, 152, 174, 92, 216, 88, 4, 115, 144, 21, 239, 42, 17,
      227, 37, 145, 183, 183, 209, 111, 118, 129, 155, 48, 176, 212, 157, 128, 225,
      171, 234, 108, 152, 34, 184, 10, 31, 223, 228, 33, 226, 111, 86, 3, 236,
      168, 164, 122, 100, 201, 160, 4, 251, 90, 248, 34, 159, 118, 47, 244, 31>>

    result = Result.new(prf, rounds, salt, digest)

    assert Mcf.encode(result) == "$pbkdf2-sha512$100000$c2FsdEtFWWJjVGNYSENCeHRqRA$rM3Nh5iuXNhYBHOQFe8qEeMlkbe30W92gZswsNSdgOGr6myYIrgKH9/kIeJvVgPsqKR6ZMmgBPta.CKfdi/0Hw"
  end

end
