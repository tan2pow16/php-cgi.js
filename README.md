# PHP-CGI.js
Copyright (c) 2022, tan2pow16. All rights reserved.  
  
A simple script to setup PHP-CGI servers using Node.js without nginx or Apache.  
<b>NOTE:</b> It's designed to be a Node.js app instead of an imported module.

## Setup
Modify the configuration file `config.json` to match your server setup.  

### Available Parameters:
 * `bin_path`: Absolute path pointing to the `php-cgi` executable.
 * `https`: Set to `true` to enable SSL.
 * `httpSlave`: (Optional) Set to `true` to enable a slave server for redirecting plain-text HTTP traffic to HTTPS. Only works with `https` enabled.
 * `httpPort`: Port for plain-text HTTP server. If `https` is enabled, the `httpSlave` server will bind to this port. Default to 80 if not specified.
 * `httpsPort`: Port for HTTPS server when `https` is enabled. Default to 443 if not specified.
 * `fallbackHttpsPrivateKey`: Path to SSL private key for HTTPS server. Used only with `https` enabled.
 * `fallbackHttpsCertificate`: Path to SSL certificate for HTTPS server. Used only with `https` enabled.
 * `hosts`: Array of sub-confgis for each hostname.
   * `domain`: Domain name for the entry.
   * `web_root`: Root directory for the web files.
   * `fallback_route`: File under `web_root` for handling default behaviors.
   * `httpsPrivateKey`: (Optional) Path to host-specific SSL private key. Used only with `https` enabled.
   * `httpsCertificate`: (Optional) Path to host-specific SSL certificate. Used only with `https` enabled.
   * `ini_path`: (Optional) Host-specific `php.ini` search directory.
 * `ini_dir`: (Optional) Default `php.ini` search directory.
 * `tmp_dir`: (Optional) Temporary file directory.
 * `error_pages`: (Optional) Array of error pages to be cached in memory.
   * `code`: HTTP status code for the entry.
   * `path`: Path to the static HTML file to be cached.

An example configuration can be found in the root directory of this package.

## Mime Types
You may modify `mimes.json` to fit your specifications for mime types used in the `Content-Type` header field.