local shortport = require "shortport"
local http = require "http"
local nmap = require "nmap"
local table = require "table"
local stdnse = require "stdnse"

description = [[
The Jupyter Notebook is a web-based interactive computing platform. Default TCP port is 8888.
]]

---
-- @usage
-- nmap -p 8888 --script jupyter-notebook-discovery.nse <target>
--
-- @output
--PORT     STATE SERVICE
--8888/tcp sun-answerbook http
--| jupyter-notebook-discovery: 
--|_  Jupyter Notebook found!
--

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.version_port_or_service(8888, "sun-answerbook", "tcp")

action = function(host, port)
  local http_response_login = http.get(host, port, "/login")
  local http_response_lab = http.get(host, port, "/lab")
  local jupyter_header = {}

  if not http_response_login or not http_response_login.status or http_response_login.status ~= 200 or not http_response_login.body then
    return
  end
  
  if not http_response_lab or not http_response_lab.status or http_response_lab.status ~= 200 or not http_response_lab.body then
    return
  end
 
  if http_response_login and http_response_lab then
    table.insert(jupyter_header, "Jupyter Notebook found!")
  end

    return stdnse.format_output(true, jupyter_header)
end
