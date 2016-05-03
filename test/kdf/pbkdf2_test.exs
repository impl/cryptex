defmodule Cryptex.Kdf.Pbkdf2Test do

  use ExUnit.Case
  alias Cryptex.Kdf.Pbkdf2
  alias Cryptex.Kdf.Pbkdf2.Result
  alias Cryptex.Mac.Hmac

  @golden_comeonin [
    {"passDATAb00AB7YxDTT", "saltKEYbcTcXHCBxtjD", 100_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 100_000,
        "c2FsdEtFWWJjVGNYSENCeHRqRA" |> Result.McfAlphabet.decode!,
        "rM3Nh5iuXNhYBHOQFe8qEeMlkbe30W92gZswsNSdgOGr6myYIrgKH9/kIeJvVgPsqKR6ZMmgBPta.CKfdi/0Hw" |> Result.McfAlphabet.decode!)},
    {"passDATAb00AB7YxDTTl", "saltKEYbcTcXHCBxtjD2", 100_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 100_000,
        "c2FsdEtFWWJjVGNYSENCeHRqRDI" |> Result.McfAlphabet.decode!,
        "WUJWsL1NbJ8hqH97pXcqeRoQ5hEGlPRDZc2UZw5X8a7NeX7x0QAZOHGQRMfwGAJml4Reua2X2X3jarh4aqtQlg" |> Result.McfAlphabet.decode!)},
    {"passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
      100_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 100_000,
        "c2FsdEtFWWJjVGNYSENCeHRqRDJQbkJoNDRBSVE2WFVPQ0VTT2hYcEVwM0hyY0dNd2JqelFLTVNhZjYzSUpl" |> Result.McfAlphabet.decode!,
        "B0R0AchXZuSu1YPeLmv1pnXqvk82GCgclWFvT8H9/m7LwcOYJ4nU/ZQdZYTvU0p4vTeuAlVdlFXo8In9tN.2uw" |> Result.McfAlphabet.decode!)},
  ]

  @golden_passlib [
    {"password", <<36, 196, 248, 159, 51, 166, 84, 170, 213, 250, 159, 211, 154, 83, 10, 193>>, 19_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 19_000,
        "JMT4nzOmVKrV.p/TmlMKwQ" |> Result.McfAlphabet.decode!,
        "jKbZHoPwUWBT08pjb/CnUZmFcB9JW4dsOzVkfi9X6Pdn5NXWeY.mhL1Bm4V9rjYL5ZfA32uh7Gl2gt5YQa/JCA" |> Result.McfAlphabet.decode!)},
    {"p@$$w0rd", <<252, 159, 83, 202, 89, 107, 141, 17, 66, 200, 121, 239, 29, 163, 20, 34>>, 19_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 19_000,
        "/J9TyllrjRFCyHnvHaMUIg" |> Result.McfAlphabet.decode!,
        "AJ3Dr926ltK1sOZMZAAoT7EoR7R/Hp.G6Bt.4DFENiYayhVM/ZBPuqjFNhcE9NjTmceTmLnSqzfEQ8mafy49sw" |> Result.McfAlphabet.decode!)},
    {"oh this is hard 2 guess", <<1, 96, 140, 17, 162, 84, 42, 165, 84, 42, 165, 244, 62, 71, 136, 177>>, 19_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 19_000,
        "AWCMEaJUKqVUKqX0PkeIsQ" |> Result.McfAlphabet.decode!,
        "F0xkzJUOKaH8pwAfEwLeZK2/li6CF3iEcpfoJ1XoExQUTStXCNVxE1sd1k0aeQlSFK6JnxJOjM18kZIdzNYkcQ" |> Result.McfAlphabet.decode!)},
    {"even more difficult", <<215, 186, 87, 42, 133, 112, 14, 1, 160, 52, 38, 100, 44, 229, 92, 203>>, 19_000,
      Pbkdf2.from_computed(
        Hmac.new(:sha512), 19_000,
        "17pXKoVwDgGgNCZkLOVcyw" |> Result.McfAlphabet.decode!,
        "TEv9woSaVTsYHLxXnFbWO1oKrUGfUAljkLnqj8W/80BGaFbhccG8B9fZc05RoUo7JQvfcwsNee19g8GD5UxwHA" |> Result.McfAlphabet.decode!)},
  ]

  test "known keys are derived correctly" do
    (@golden_comeonin ++ @golden_passlib) |> Enum.map(fn {secret, salt, rounds, computed} ->
      assert Pbkdf2.derive(Hmac.new(:sha512), secret, salt, rounds: rounds) == computed
    end)
  end

  test "derive with function is equivalent to new followed by derive" do
    assert Pbkdf2.new(Hmac.new(:sha512)) |> Pbkdf2.derive("test", "salt") == Pbkdf2.derive(Hmac.new(:sha512), "test", "salt")
  end

  test "salt generation works correctly" do
    assert byte_size(Pbkdf2.derive(Hmac.new(:sha512), "test") |> Result.salt) == 16
    assert byte_size(Pbkdf2.derive(Hmac.new(:sha512), "test", nil, salt_size: 32) |> Result.salt) == 32
    assert_raise ArgumentError, ~r/must be at least/i, fn ->
      Pbkdf2.derive(Hmac.new(:sha512), "test", nil, salt_size: 4)
    end
  end

  test "invalid hash size raises" do
    assert_raise ArgumentError, ~r/must be a multiple/i, fn ->
      Pbkdf2.derive(Hmac.new(:sha512), "test", "salt", hash_size: 42)
    end

    assert_raise ArgumentError, ~r/hash size must be greater than 0/i, fn ->
      Pbkdf2.derive(Hmac.new(:sha512), "test", "salt", hash_size: 0)
    end
  end

  test "invalid number of rounds raises" do
    assert_raise ArgumentError, ~r/rounds must be greater than 0/i, fn ->
      Pbkdf2.derive(Hmac.new(:sha512), "test", "salt", rounds: 0)
    end
  end

end
