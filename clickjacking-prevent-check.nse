local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Verify if the X-Frame-Options (RFC 7034) is enabled in a web service and show the permissive level configured.

X-Frame-Options is a HTTP header field (policy) that allows the server to communicate to the browser to display or not the content of the frames included in the current page that are part of other web pages.

It allows to prevent/difficulty the execution of clickjacking attack.

References: 

https://www.ietf.org/rfc/rfc7034.txt
https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options#
]]

---
-- @usage
-- nmap -p <port> --script clickjacking-prevent-check <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | clickjacking-prevent-check:
-- |  X-Frame-Options is configured.
-- |  Header: X-Frame-Options: DENY
-- |_ Description: The browser must not display this content in any frame.
--
-- @args clickjacking-prevent-check.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local response
  local output_info = {}
  local xframe_header = {}

  response = http.head(host, port, path)

  if response == nil then
    return fail("Request failed")
  end

  if response.rawheader == nil then
    return fail("Response didn't include a proper header")
  end

  for _,line in pairs(response.rawheader) do
    if line:match("X.Frame.Options") or line:match("x.frame.options") then
      table.insert(xframe_header, line)
    end
  end

  if #xframe_header > 0 then
    table.insert(output_info, "X-Frame-Options is configured.")
    table.insert(output_info, "Header: " .. table.concat(xframe_header, " "))

    for _,line in pairs(xframe_header) do
      if line:match("DENY") or line:match("deny") then
        table.insert(output_info, "Description: The browser must not display this content in any frame.")
      elseif line:match("SAMEORIGIN") or line:match("sameorigin") then
        table.insert(output_info, "Description: The browser must not display this content in any frame from a page of different origin than the content itself.")
      elseif line:match("ALLOW.FROM") or line:match("allow.from") then
        table.insert(output_info, "Description: The browser must not display this content in a frame from any page with a top-level browsing context of different origin than the specified origin.")
      end
    end

  else
    table.insert(output_info, "X-Frame-Options is not configured.")
    table.insert(output_info, "Description: This web application/service is vulnerable to Clickjacking Attack.")
  end

  return stdnse.format_output(true, output_info)

end
