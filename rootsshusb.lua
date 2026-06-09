module(..., package.seeall)

local json = require("json")
local log = require("log").logger("auto.p.rootsshusb")

local STAGE = "/data/rootsshusb"
local RESULT = STAGE .. "/result.json"
local moduleObj

local function new(self)
  local obj = {}
  setmetatable(obj, self)
  self.__index = self
  return obj
end

function instance(self)
  if not moduleObj then
    moduleObj = new(self)
  end
  return moduleObj
end

local function readAll(path)
  local f, err = io.open(path, "rb")
  if not f then
    return nil, err
  end
  local data = f:read("*a")
  f:close()
  return data
end

local function writeAll(path, data)
  local f, err = io.open(path, "wb")
  if not f then
    return nil, err
  end
  f:write(data or "")
  f:close()
  return true
end

local function dirname(path)
  return string.match(path, "^(.*)/[^/]+$") or "/"
end

local function shellQuote(path)
  return "'" .. string.gsub(path, "'", "'\\''") .. "'"
end

local function mkdir(path)
  os.execute("mkdir -p " .. shellQuote(path))
end

local function base64Decode(data)
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  data = string.gsub(data or "", "[^" .. alphabet .. "=]", "")
  return (data:gsub(".", function(ch)
    if ch == "=" then
      return ""
    end
    local value = string.find(alphabet, ch, 1, true)
    if not value then
      return ""
    end
    value = value - 1
    local bits = ""
    for i = 6, 1, -1 do
      if value % (2 ^ i) - value % (2 ^ (i - 1)) > 0 then
        bits = bits .. "1"
      else
        bits = bits .. "0"
      end
    end
    return bits
  end):gsub("%d%d%d?%d?%d?%d?%d?%d?", function(bits)
    if #bits ~= 8 then
      return ""
    end
    local value = 0
    for i = 1, 8 do
      if string.sub(bits, i, i) == "1" then
        value = value + 2 ^ (8 - i)
      end
    end
    return string.char(value)
  end))
end

local function result(ok, extra)
  local body = extra or {}
  body.ok = ok and true or false
  body.updatedAt = os.time()
  mkdir(STAGE)
  writeAll(RESULT, json.encode(body))
  return body
end

local function install()
  local manifestText, err = readAll(STAGE .. "/manifest.json")
  if not manifestText then
    error("manifest read failed: " .. tostring(err))
  end

  local manifest = json.decode(manifestText)
  if type(manifest) ~= "table" then
    error("manifest did not decode to a table")
  end

  local installed = {}
  for _, file in ipairs(manifest.files or {}) do
    if type(file.path) ~= "string" or type(file.id) ~= "string" then
      error("invalid staged file entry")
    end

    local chunks = tonumber(file.chunks or 0) or 0
    if chunks < 1 then
      error("invalid chunk count for " .. file.path)
    end

    local parts = {}
    for i = 1, chunks do
      local chunkPath = STAGE .. "/chunks/" .. file.id .. "." .. tostring(i)
      local chunk, chunkErr = readAll(chunkPath)
      if not chunk then
        error("chunk read failed " .. chunkPath .. ": " .. tostring(chunkErr))
      end
      table.insert(parts, chunk)
    end

    local data = base64Decode(table.concat(parts, ""))
    if file.bytes and #data ~= tonumber(file.bytes) then
      error("size mismatch for " .. file.path .. ": got " .. tostring(#data) .. " expected " .. tostring(file.bytes))
    end

    mkdir(dirname(file.path))
    local ok, writeErr = writeAll(file.path, data)
    if not ok then
      error("write failed for " .. file.path .. ": " .. tostring(writeErr))
    end

    if file.mode and string.match(file.mode, "^[0-7][0-7][0-7]$") then
      os.execute("chmod " .. file.mode .. " " .. shellQuote(file.path))
    end
    table.insert(installed, {path = file.path, bytes = #data, mode = file.mode or ""})
  end

  local commandResults = {}
  for _, command in ipairs(manifest.commands or {}) do
    if type(command) == "string" and command ~= "" then
      local rc = os.execute(command)
      table.insert(commandResults, {command = command, rc = rc})
    end
  end

  log.notice("rootsshusb installed", #installed, "files")
  return result(true, {
    installed = installed,
    commands = commandResults,
    version = manifest.version or "unknown"
  })
end

function discover(self)
  local ok, data = pcall(install)
  if not ok then
    log.notice("rootsshusb install failed:", data)
    result(false, {error = tostring(data)})
    return {}
  end
  return {
    ["rootssh-usb"] = {
      id = "rootssh-usb",
      type = "rootsshusb",
      name = "Root SSH USB Installer",
      status = data
    }
  }
end

function status(self)
  local data = readAll(RESULT) or "{}"
  return {state = "ready", result = data}
end
