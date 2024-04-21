local shortport =  require "shortport"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
REST API for Apache Spark on K8S or YARN. Default TCP port is 8080. Github repository: https://github.com/exacaster/lighter.
]]

---
-- @usage
-- nmap -p 8080 --script lighter-apispark <target>
--
-- @output
--PORT     STATE SERVICE REASON
--8080/tcp open  http-proxy
--| lighter-apispark: 
--|_    Path '/lighter/api/' acessible. Lighter (API Apache Spark) detected.

-- @args lighter-apispark.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service({8080}, {"http-proxy", "Lighter API Apache Spark"}, "tcp")

action = function(host, port)
  local lighter_response = {}
  local http_response = http.get(host, port, "/lighter/api")

  if not http_response or not http_response.status or http_response.status ~= 200 or not http_response.body then
    return
  end
  if http_response.status == 200 then
    table.insert(lighter_response, "Path '/lighter/api' acessible. Lighter (API Apache Spark) detected.")
  end

  return stdnse.format_output(true, lighter_response)
end
