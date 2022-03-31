# NSE_scripts
NSE script to use with nmap tool.

**http-hsts-verify**: Verify that HTTP Strict Transport Security (RFC 6797) is enabled in the target.

**clickjacking-prevent-check**: Verify if the X-Frame-Options (RFC 7034) is enabled in a web service and show the permissive level configured.

These two scripts became one in the "http-security-headers.nse", link in the project: https://nmap.org/nsedoc/scripts/http-security-headers.html

**jenkins-info.nse**: Verify info exposed by default in the Jenkins service.

**docker-api-exposed.nse**: Verify if a Docker API is running on a host, also list all containers activated.

**dkron-discovery.nse**: Verify if a dKron service is running on a host, also will inform the installed version.

**jupyter-notebook-discovery.nse**: Verify if a Jupyter Notebook is running on a host.
