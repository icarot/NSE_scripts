local shortport =  require "shortport"
local http = require "http"
local nmap = require "nmap"
local json = require "json"

description = [[
Docker Registry exposed to internet/intranet is dangerous, because it allows an external user to manage the images in the Docker Registry Server. Default TCP port is 5000.
]]

---
-- @usage
-- nmap -p 5000 --script docker-registry-exposed <target>
--
-- @output
--PORT     STATE SERVICE REASON
--5000/tcp open  http    Docker Registry (API: 2.0)
--| docker-registry-exposed: 
--|   repositories: 
--|_    ubuntu
    
-- @args docker-api-exposed.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service({5000}, {"upnp", "http    Docker Registry (API: 2.0)"}, "tcp")

action = function(host, port)
 local http_response = http.get(host, port, "/v2/_catalog")
	
 if not http_response or not http_response.status or http_response.status ~= 200 or not http_response.body then
  return
 end

 local parsed_json, response = json.parse(http_response.body)

 if(parsed_json) then
   return response
  end
end
