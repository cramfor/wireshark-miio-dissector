local p_miio = Proto("miio", "Xiaomi Mi Home Binary Protocol")
p_miio.prefs.token = Pref.string("Device token", "", "128-bit device token (32 hex chars)")

local f_magic = ProtoField.uint16("miio.magic", "Magic", base.HEX)
local f_length = ProtoField.uint16("miio.length", "Length", base.DEC)
local f_unknown = ProtoField.uint32("miio.unknown", "Unknown", base.HEX)
local f_deviceId = ProtoField.uint32("miio.deviceId", "DeviceID", base.HEX)
local f_ts = ProtoField.uint32("miio.ts", "Timestamp", base.DEC)
local f_checksum = ProtoField.bytes("miio.checksum", "Checksum")
local f_encryptd_data = ProtoField.bytes("miio.encryptd_data", "Encrypted data")
local f_decrypted_data = ProtoField.string("miio.data", "Data")
local f_decrypt_err = ProtoField.string("miio.error", "Decrypt Error")
p_miio.fields = { f_magic, f_length, f_unknown, f_deviceId, f_ts, f_checksum, f_encryptd_data, f_decrypted_data, f_decrypt_err }

--------------------------------------------------------------------------------
-- 纯 Lua MD5 实现
--------------------------------------------------------------------------------
local md5_k = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
}

local md5_s = {
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
}

local function md5_raw(msg)
  local orig_len = #msg
  msg = msg .. "\x80"
  local pad_len = (56 - (#msg % 64)) % 64
  msg = msg .. string.rep("\0", pad_len) .. string.pack("<I8", orig_len * 8)

  local a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

  for offset = 1, #msg, 64 do
    local M = {}
    for j = 0, 15 do
      M[j + 1] = string.unpack("<I4", msg, offset + j * 4)
    end

    local A, B, C, D = a0, b0, c0, d0
    for i = 0, 63 do
      local F, g
      if i < 16 then
        F = (B & C) | ((~B) & D)
        g = i + 1
      elseif i < 32 then
        F = (D & B) | ((~D) & C)
        g = (5 * i + 1) % 16 + 1
      elseif i < 48 then
        F = B ~ C ~ D
        g = (3 * i + 5) % 16 + 1
      else
        F = C ~ (B | (~D))
        g = (7 * i) % 16 + 1
      end

      F = (F + A + md5_k[i + 1] + M[g]) & 0xffffffff
      A = D
      D = C
      C = B
      local shift = md5_s[i + 1]
      B = (B + (((F << shift) | (F >> (32 - shift))) & 0xffffffff)) & 0xffffffff
    end

    a0 = (a0 + A) & 0xffffffff
    b0 = (b0 + B) & 0xffffffff
    c0 = (c0 + C) & 0xffffffff
    d0 = (d0 + D) & 0xffffffff
  end

  return string.pack("<I4I4I4I4", a0, b0, c0, d0)
end

local function hex_to_raw(hex)
  return (hex:gsub("..", function(cc)
    return string.char(tonumber(cc, 16))
  end))
end

local function raw_to_hex(raw)
  return (raw:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end))
end

--------------------------------------------------------------------------------
-- 密钥派生与 AES-128-CBC 解密
--------------------------------------------------------------------------------
local cached_token = ""
local cached_token_raw = nil
local cached_key = nil
local cached_iv = nil

local function derive_key_iv(token_hex)
  local clean_token = string.gsub(token_hex or "", "%s+", "")
  if #clean_token ~= 32 then
    return nil, nil, nil, "Token length must be 32 hex chars (got " .. #clean_token .. ")"
  end

  if clean_token == cached_token and cached_key and cached_iv then
    return cached_key, cached_iv, cached_token_raw, nil
  end

  local token_raw = hex_to_raw(clean_token)
  local key_raw = md5_raw(token_raw)
  local iv_raw = md5_raw(key_raw .. token_raw)

  cached_token = clean_token
  cached_token_raw = token_raw
  cached_key = ByteArray.new(raw_to_hex(key_raw))
  cached_iv = ByteArray.new(raw_to_hex(iv_raw))
  return cached_key, cached_iv, cached_token_raw, nil
end

local CIPHER_AES128 = GCRY_CIPHER_AES128 or 7
local MODE_CBC      = GCRY_CIPHER_MODE_CBC or 3

local function aes_128_cbc_decrypt(data_bytes, key_bytes, iv_bytes)
  local cipher = GcryptCipher.open(CIPHER_AES128, MODE_CBC, 0)
  cipher:setkey(key_bytes)
  cipher:setiv(iv_bytes)

  -- Wireshark Lua GcryptCipher:decrypt(buf) 支持就地解密（直接修改传入的 ByteArray）
  local work_buf = ByteArray.new(data_bytes:tohex())
  local res = cipher:decrypt(work_buf)
  local target = res or work_buf

  local raw_str = target:raw()
  local str_len = #raw_str
  if str_len > 0 then
    local pad_len = string.byte(raw_str, str_len)
    if pad_len > 0 and pad_len <= 16 and pad_len <= str_len then
      raw_str = string.sub(raw_str, 1, str_len - pad_len)
    end
  end
  raw_str = string.gsub(raw_str, "%z+$", "")
  return raw_str
end

local json_dis = Dissector.get("json")

local function miio_dissector(buf, pkt, root)
  if buf:len() < 32 then return false end

  local magic = buf(0, 2)
  if magic:uint() ~= 0x2131 then return false end

  local len = buf(2, 2)
  if buf:len() ~= len:uint() then return false end

  pkt.cols.protocol = "MIIO"

  local unknown = buf(4, 4)
  local deviceId = buf(8, 4)
  local ts = buf(12, 4)
  local checksum = buf(16, 16)

  local t = root:add(p_miio, buf)
  if len:uint() == 32 then
    if deviceId:uint() == 0xffffffff then
      pkt.cols.info = "Hello"
    else
      pkt.cols.info = "Hello Ack"
    end
  end

  t:add(f_magic, magic)
  t:add(f_length, len)
  t:add(f_unknown, unknown)
  t:add(f_deviceId, deviceId)
  t:add(f_ts, ts)
  t:add(f_checksum, checksum)

  if len:uint() > 32 then
    local data = buf(32, len:uint() - 32)
    local key, iv, token_raw, token_err = derive_key_iv(p_miio.prefs.token)
    if key and iv then
      local header_prefix = hex_to_raw(buf(0, 16):bytes():tohex())
      local enc_raw = hex_to_raw(data:bytes():tohex())
      local calc_checksum = raw_to_hex(md5_raw(header_prefix .. token_raw .. enc_raw)):lower()
      local pkt_checksum = checksum:bytes():tohex():lower()

      if calc_checksum ~= pkt_checksum then
        t:add(f_encryptd_data, data)
        t:add(f_decrypt_err, "Token mismatch! Checksum expected " .. calc_checksum .. ", got " .. pkt_checksum)
        return true
      end

      local ok, decrypted_data = pcall(aes_128_cbc_decrypt, data:bytes(), key, iv)
      if ok and decrypted_data and #decrypted_data > 0 then
        pkt.cols.info = decrypted_data
        t:add(f_decrypted_data, data, decrypted_data)
        -- 同时调用 Wireshark 内置 JSON 解析器展开结构化字段
        if json_dis then
          local json_tvb = ByteArray.new(raw_to_hex(decrypted_data)):tvb("Decrypted MIIO JSON")
          json_dis:call(json_tvb, pkt, root)
        end
      else
        t:add(f_encryptd_data, data)
        t:add(f_decrypt_err, "Decrypt failed: " .. tostring(decrypted_data))
      end
    else
      t:add(f_encryptd_data, data)
      if token_err then
        t:add(f_decrypt_err, token_err)
      end
    end
  end

  return true
end

local data_dis = Dissector.get("data")
function p_miio.dissector(buf, pkt, root)
  if not miio_dissector(buf, pkt, root) then
    data_dis:call(buf, pkt, root)
  end
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(54321, p_miio)
