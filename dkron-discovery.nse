local shortport =  require "shortport"
local http = require "http"
local nmap = require "nmap"

description = [[
Dkron is a system service for workload automation that runs scheduled jobs, just like the cron unix service but distributed in several machines in a cluster. Default TCP port is 8080.
]]

---
-- @usage
-- nmap -p 8080 --script dkron-discovery.nse <target>
--
-- @output
--PORT     STATE SERVICE
--8080/tcp open  dkron
--| dkron-discovery: 
--| 	Installed version: 3.0.6
--|_	Directory /dashboard is accessible!
--
-- @args dkron-discovery.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service(8080, "dkron", "tcp")

action = function(host, port)
  local http_response = http.get(host, port, "/dashboard")
  local dkron_response

  if not http_response or not http_response.status or http_response.status ~= 200 or not http_response.body then
    return
  end
  
  if string.match(http_response.rawbody, "Dkron %d.%d.%d") then
    dkron_version = string.match(http_response.rawbody, "%d.%d.%d")
    port.version.name = "dkron"
    port.version.version = dkron_version
    port.version.product = "dKron"
    nmap.set_port_version(host, port)
    dkron_response = "\n\tInstalled version: " .. dkron_version .. "\n\tDirectory /dashboard is accessible!"

    return dkron_response
  end
end
