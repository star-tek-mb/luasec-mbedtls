------------------------------------------------------------------------------
-- LuaSec 0.4.1
-- Copyright (C) 2006-2011 Bruno Silvestre
--
------------------------------------------------------------------------------

module("tls", package.seeall)

local core = require("tls.core")
local context = require("tls.context")

local function readfile(path)
    local file = io.open(path, 'rb')
    if not file then return '' end
    local content = file:read("*a")
    return content
end

local function newcontext(cfg)
    if cfg.mode == 'client' then
        local cafile = cfg.cafile
        if cfg.fileMode then
            cafile = readfile(cfg.cafile)
        end
        return context.create(cfg.mode, cfg.verify, cafile)
    else
        local key, certificate, cafile = cfg.key, cfg.certificate, cfg.cafile
        if cfg.fileMode then
            key = readfile(cfg.key)
            certificate = readfile(cfg.certificate)
            cafile = readfile(cfg.cafile)
        end
        return context.create(cfg.mode, cfg.verify, key, certificate, cafile)
    end
   return nil
end

local function wrap(sock, cfg)
   local ctx, msg
   if type(cfg) == "table" then
      ctx, msg = newcontext(cfg)
      if not ctx then return nil, msg end
   else
      ctx = cfg
   end

   local s = core.create(ctx)
   if s then
      core.setfd(s, sock:getfd())
      sock:setfd(-1)
      return s
   end

   return nil, msg
end


local _M = {
    newcontext = newcontext,
    wrap = wrap
}

return _M