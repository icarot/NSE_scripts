local shortport =  require "shortport"
local http = require "http"
local nmap = require "nmap"
local json = require "json"

description = [[
Docker API exposed to internet/intranet is dangerous, because it allows an external user to manage the containers in the server. Default TCP port is 2375.
]]

---
-- @usage
-- nmap -p 2375 --script docker-api-exposed <target>
--
-- @output
--PORT     STATE SERVICE REASON
--2375/tcp open  docker  syn-ack
--| docker-api-exposed: 
--|   
--|     Created: 1602434001
--|     Labels: 
--| 
--|     Command: /bin/sh
--|     HostConfig: 
--|       NetworkMode: default
--|     ImageID: sha256:a24b...
--|     Id: e252...
--|     Mounts: 
--| 
--|     Names: 
--|       /random_name
--|     Status: Up 13 hours
--|     NetworkSettings: 
--|       Networks: 
--|         bridge: 
--|           MacAddress: 02:42:xx:xx:xx:xx
--|           IPv6Gateway: 
--|           EndpointID: bd8...
--|           IPAddress: 172.17.0.xx
--|           NetworkID: f52...
--|           DriverOpts: 
--| 
--|           IPPrefixLen: 16
--|           Gateway: 172.17.0.xx
--|           Links: 
--| 
--|           IPAMConfig: 
--| 
--|           GlobalIPv6PrefixLen: 0
--|           Aliases: 
--| 
--|           GlobalIPv6Address: 
--|     Ports: 
--| 
--|     State: running
--|_    Image: alpine

-- @args docker-api-exposed.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service({2375, 2376}, {"docker", "docker-s"}, "tcp")

action = function(host, port)
 local http_response = http.get(host, port, "/containers/json")
	
 if not http_response or not http_response.status or http_response.status ~= 200 or not http_response.body then
  return
 end

 local parsed_json, response = json.parse(http_response.body)

 if(parsed_json) then
   return response
  end
end
