local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Jenkins is an open source automation server (Java programming language). It is
a fork from Hudson project. Default TCP port is 8080. Project's home page: https://wiki.jenkins-ci.org/display/JENKINS/Home
]]

---
-- @usage
-- nmap -p <port> --script jenkins-info <target>
--
-- @output
-- PORT    STATE SERVICE
-- 8080/tcp open  http-proxy
-- | jenkins-info:
-- |   Hudson Theme: default
-- |   Hudson Version: 1.391
-- |   Jenkins Version: 1.622
-- |   Jenkins Session ID: 214322fe79
-- |   Hudson CLI Port: 43281
-- |   Jenkins CLI Port: 43281
-- |   Jenkins CLI2 Port: 43281
-- |   Instance Identity: AWWWGGj54BmRRBfwIkcsMYvd/ss44settttLvAV9GBVv4FdlTxhvvvvX25NyrqeayJb80DAgPX4mPFZzPzvZcq5naOkZDaEP+UrIs8qry53lVJEy8XW5F/58dor59j5fM39LhPMCJsZCfWP49ioy4vtu4TAzogiEJv71uXrCX5dA4SWxXNLhehfra6eOuuu27663vvsnnayyyslc8BTvbMLWRTcZeFUuvhBpmhKHQKKyaHm35aVBHaCRjEL2u6jat9pQIDAQABA
-- |   SSH Endpoint Port: 37376
-- |_  Server: Jetty(winstone-2.6)

-- @args jenkins-info.path The URL path to request. The default path is "/".

author = "Icaro Torres (iBLISS Labs)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

 action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local response
  local output_info = {}
  local jenkins_header = {}
  local temp

  response = http.get(host, port, path)

  if response == nil then
    return fail("Request failed")
  end

  if response.rawheader == nil then
    return fail("Response didn't include a proper header")
  end

 for _,line in pairs(response.rawheader) do

    if line:match("X.Hudson.Theme:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
     table.insert(jenkins_header, "Hudson Theme:" .. temp)
    end

    if line:match("X.Hudson:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Hudson Version:" .. temp)
    end

    if line:match("X.Jenkins:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Jenkins Version:" .. temp)
    end

    if line:match("X.Jenkins.Session:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Jenkins Session ID:" .. temp)
    end

    if line:match("X.Hudson.CLI.Port:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Hudson CLI Port:" .. temp)
    end

    if line:match("X.Jenkins.CLI.Port:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Jenkins CLI Port:" .. temp)
    end

    if line:match("X.Jenkins.CLI2.Port:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Jenkins CLI2 Port:" .. temp)
    end

    if line:match("X.Instance.Identity:") then
      _, temp = line.match(line, "([^,]+):([^,]+)")
      table.insert(jenkins_header, "Instance Identity:" .. temp)
    end

    if line:match("X.SSH.Endpoint:") then
      _, temp = line.match(line, "([^,]+):(%d+)")
      table.insert(jenkins_header, "SSH Endpoint Port: " .. temp)
    end

    if line:match("Server:") then
      temp = line.match(line, ":([^,]+)")
      table.insert(jenkins_header, "Server:" .. temp)
    end

  end

  return stdnse.format_output(true, jenkins_header)

end
