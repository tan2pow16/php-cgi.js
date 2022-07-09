'use strict';

/**
 * Copyright (c) 2022, tan2pow16. All rights reserved.
 * 
 * @author {tan2pow16}
 * A simple Node.js app that works as a PHP-CGI HTTP(S) server.
 */

const child_process = require('child_process');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const tls = require('tls');
const url = require('url');

/**
 * 
 * @param {String} _path 
 * @returns {boolean}
 */
function path_is_absolute(_path)
{
  return path.normalize(_path) === path.resolve(_path);
}

/**
 * 
 * @param {Object} headers 
 * @param {Object} ret 
 * @returns {Object}
 */
function cgi_env_setup(headers, ret)
{
  for(let key in headers)
  {
    switch(key.toLowerCase())
    {
      case 'content-length':
      {
        ret['CONTENT_LENGTH'] = `${headers[key]}`;
        break;
      }
      case 'content-type':
      {
        ret['CONTENT_TYPE'] = headers[key];
        break;
      }
      case 'authorization':
      {
        idx = headers[key].indexOf(' ');
        if(idx >= 0)
        {
          ret['AUTH_TYPE'] = headers[key].substring(0, idx);
          ret['REMOTE_USER'] = headers[key].substring(idx + 1);
        }
        else
        {
          ret['AUTH_TYPE'] = headers[key];
          ret['REMOTE_USER'] = 'NULL';
        }
        break;
      }
      default:
      {
        ret[`HTTP_${key.toUpperCase().replace(/-/g, '_')}`] = headers[key];
      }
    }
  }

  return ret;
}

/**
 * 
 * @param {Buffer} buf 
 * @returns {Object}
 */
function construct_resp_headers(buf)
{
  let arr = buf.toString('utf-8').split(/\r\n/g);

  let ret = {
    code: 200,
    values: {}
  }

  for(let i = 0 ; i < arr.length ; i++)
  {
    let idx = arr[i].indexOf(':');
    if(idx > 0)
    {
      let key = arr[i].substring(0, idx).trim();
      let val = arr[i].substring(idx + 1).trim();
      switch(key)
      {
        // 'header()' called in the php script
        case 'Status':
        {
          ret.code = Number(val.split(' ')[0]);
          if(!Number.isInteger(ret.code))
          {
            ret.code = 500;
          }
          break;
        }
        default:
        {
          ret.values[key] = val;
        }
      }
    }
    else
    {
      ret.values[arr[i].trim()] = '';
    }
  }

  return ret;
}

/**
 * @param {Object} conf 
 * @param {http.ClientRequest} req 
 * @param {http.ServerResponse} resp 
 */
function php_cgi(conf, req, resp)
{
  let hostname = req.headers['host'];

  // Request hostname is not allowed in the configuration
  // conf.hosts will be a Map() object.
  if(!conf.hosts.has(hostname))
  {
    reply_error(404, conf, resp);
    return;
  }
  let host_conf = conf.hosts.get(hostname);

  let cgi_env = Object.assign({}, process.env);

  cgi_env['SERVER_SOFTWARE'] = `node/${process.version.substring(1)}`;
  cgi_env['SERVER_PROTOCOL'] = 'HTTP/1.1';
  cgi_env['GATEWAY_INTERFACE'] = 'CGI/1.1';
  cgi_env['SERVER_NAME'] = hostname;
  cgi_env['REQUEST_METHOD'] = req.method;
  cgi_env['REQUEST_URI'] = req.url;
  cgi_env['REDIRECT_STATUS'] = 0;

  let remote_addr = req.socket.remoteAddress;
  if(remote_addr.indexOf('.') > 0)
  {
    // Strip hybrid IPv6 artifact from an IPv4 address.
    remote_addr = remote_addr.substring(remote_addr.lastIndexOf(':') + 1);
  }
  cgi_env['REMOTE_ADDR'] = remote_addr;

  if(conf.tmp_dir)
  {
    cgi_env['TMPDIR'] = conf.tmp_dir;
    cgi_env['TEMP'] = conf.tmp_dir;
    cgi_env['TMP'] = conf.tmp_dir;
  }

  if(conf.https)
  {
    cgi_env['HTTPS'] = 'On';
    cgi_env['SERVER_PORT'] = conf.httpsPort;
  }
  else
  {
    cgi_env['HTTPS'] = 'Off';
    cgi_env['SERVER_PORT'] = conf.httpPort;
  }

  let req_url = url.parse(req.url);
  let decoded_path;
  try
  {
    decoded_path = decodeURIComponent(req_url.pathname);
  }
  catch(err)
  {
    console.error(err);
    reply_error(400, conf, resp);
    return;
  }

  // host_conf['web_root'] will be canonical before passing into the function.
  let web_root = host_conf['web_root'];
  let fallback = null;
  if(!web_root.endsWith(path.sep))
  {
    web_root += path.sep;
  }
  let path_info = path.normalize(`${web_root}${decoded_path}`);
  if(!path_info.startsWith(web_root))
  {
    // Prevent path traversal.
    reply_error(403, conf, resp);
    return;
  }
  else if(!fs.existsSync(path_info))
  {
    if(host_conf.fallback_route)
    {
      fallback = host_conf.fallback_route;
    }
    else
    {
      reply_error(404, conf, resp);
      return;
    }
  }
  else
  {
    let file_stats = fs.statSync(path_info);
    if(file_stats.isDirectory())
    {
      let path_test = path.resolve(`${path_info}${path.sep}index.php`);
      let test_stats;
      if(fs.existsSync(path_test) && (test_stats = fs.statSync(path_test)).isFile())
      {
        path_info = path_test;
        file_stats = test_stats;
        decoded_path = path.posix.normalize(`${decoded_path}/index.php`);
      }
      else
      {
        path_test = path.resolve(`${path_info}${path.sep}index.html`);
        if(fs.existsSync(path_test) && (test_stats = fs.statSync(path_test)).isFile())
        {
          path_info = path_test;
          file_stats = test_stats;
        }
        else
        {
          if(host_conf.fallback_route)
          {
            fallback = host_conf.fallback_route;
          }
          else
          {
            reply_error(403, conf, resp);
            return;
          }
        }
      }
    }
    
    if(!fallback && !path_info.toLowerCase().endsWith('.php'))
    {
      let mime = 'application/octet-stream';
      let dot = path_info.lastIndexOf('.');
      if(dot >= 0)
      {
        mime = conf.mimes[path_info.substring(dot)] || mime;
      }
      resp.writeHead(200, {
        'Content-Length': file_stats.size,
        'Content-Type': mime
      });

      let file = fs.openSync(path_info, 'r');
      let BUF_LEN = 4096;
      let cache = Buffer.allocUnsafe(BUF_LEN);
      let buf = null;
      let len = -1;
      while((len = fs.readSync(file, cache)) > 0)
      {
        buf = Buffer.allocUnsafe(len);
        // Clearly Node.js did not properly implement buffer in write streams and
        //  the data passed into stream.write(buf) function is NOT deep-copied.
        // Thus we have to make a copy on our own instead of overwriting the cache.
        // Big LMFAO to the library implementation stupidity here.
        cache.copy(buf, 0, 0, len);
        resp.write(buf);
      }
      fs.closeSync(file);
      resp.end();

      return;
    }
  }

  // web_root = web_root.replace(/\\/g, '/');
  // path_info = path_info.replace(/\\/g, '/');

  cgi_env['SERVER_ROOT'] = web_root;
  cgi_env['DOCUMENT_ROOT'] = web_root;

  // cgi_env['PATH_INFO'] = path_info;
  cgi_env['PATH_INFO'] = ''; // This is a bug in PHP-CGI that incorrectly set 'PHP_SELF' to a duplicated string.

  cgi_env['PATH_TRANSLATED'] = path_info;
  cgi_env['QUERY_STRING'] = req_url.query ? req_url.query : '';

  // The requested file doesn't actually exist or accessible, but a default router has been set.
  //  Thus, use the router file instead!
  if(fallback)
  {
    cgi_env['SCRIPT_NAME'] = fallback;
    cgi_env['SCRIPT_FILENAME'] = path.resolve(`${web_root}${fallback}`);
  }
  else
  {
    cgi_env['SCRIPT_NAME'] = decoded_path;
    cgi_env['SCRIPT_FILENAME'] = path_info;
  }

  cgi_env_setup(req.headers, cgi_env);

  // conf['bin_path'] should be checked for existence during the configuration setup process.
  let argv = [];
  if(host_conf['ini_dir'])
  {
    cgi_env['PHPRC'] = host_conf['ini_dir'];
  }
  else if(conf['ini_dir'])
  {
    cgi_env['PHPRC'] = conf['ini_dir'];
  }
  let cgi_proc = child_process.spawn(conf['bin_path'], argv, {env: cgi_env});

  let resp_header = false;
  cgi_proc.on('error', function(err) {
    console.error(err);
    resp_header = true;
    reply_error(500, conf, resp);
  });

  let len = req.headers['content-length'] || 0;
  req.on('data', function(buf) {
    len -= buf.length;
    cgi_proc.stdin.write(buf);
  });

  req.on('end', function() {
    // Pad bad content length request.
    if(len > 0)
    {
      let BUF_LEN = 4096;
      let buf = Buffer.allocUnsafe(BUF_LEN);
      while(len > BUF_LEN)
      {
        cgi_proc.stdin.write(buf);
        len -= BUF_LEN;
      }
      cgi_proc.stdin.end(Buffer.allocUnsafe(len));
    }
    
    let sep = Buffer.from('\r\n\r\n', 'utf-8');
    let cache = Buffer.allocUnsafe(0);
    let header_test_idx = 0;
    cgi_proc.stdout.on('data', function(buf) {
      if(!resp_header)
      {
        cache = Buffer.concat([cache, buf]);
        if((header_test_idx = cache.indexOf(sep, header_test_idx)) >= 0)
        {
          let resp_headers = construct_resp_headers(cache.subarray(0, header_test_idx));
          resp.writeHead(resp_headers.code, resp_headers.values);

          resp_header = true;
          resp.write(cache.subarray(header_test_idx + sep.length));
        }
        else
        {
          header_test_idx = Math.max(cache.length - sep.length, 0);
        }
      }
      else
      {
        resp.write(buf);
      }
    });
    cgi_proc.stdout.on('end', function() {
      resp.end();
    });

    cgi_proc.stderr.on('data', function(buf) {
      process.stderr.write(buf);
    });
    cgi_proc.stderr.on('end', function() {
      // Do nothing for now.
    });
  });
}

/**
 * 
 * @param {number} code 
 * @param {Object} conf 
 * @param {http.ServerResponse} resp 
 */
function reply_error(code, conf, resp)
{
  let reply = conf.error_pages[code] || Buffer.allocUnsafe(0);
  resp.writeHead(code, {
    'Content-Length': reply.length,
    'Content-Type': 'text/html'
  });
  resp.end(reply);
}

/**
 * @param {http.ClientRequest} req 
 * @param {http.ServerResponse} resp 
 */
function http_slave_handler(req, resp)
{
  try
  {
    resp.writeHead(301, {
      'Location': `https://${req.headers.host}${req.url}`
    });
    resp.end();
  }
  catch(err)
  {
    console.error(err);
  }
}

/**
 * 
 * @param {Object} conf 
 */
function setup_server(conf)
{
  if(conf.https)
  {
    globalThis.https_server = https.createServer({
      SNICallback: function(domain, ret_callback) {
        let host_conf = conf.hosts.get(domain);
        let ret = null;
        if(host_conf)
        {
          let ret = host_conf.ssl_ctx || ret;
        }
        ret_callback(null, ret);
      },
      key: conf.httpsPrivateKey,
      cert: conf.httpsCertificate
    }, function(req, resp) {
      php_cgi(conf, req, resp);
    }).listen(conf.httpsPort);

    if(conf.httpSlave)
    {
      globalThis.http_server = http.createServer(http_slave_handler).listen(conf.httpPort);
    }
  }
  else
  {
    globalThis.http_server = http.createServer(function(req, resp) {
      php_cgi(conf, req, resp);
    }).listen(conf.httpPort);
  }
}

function getMimeMap()
{
  let mimes_json = JSON.parse(fs.readFileSync(`${__dirname}/mimes.json`));
  let ret = {};
  for(let ext in mimes_json)
  {
    ret[`.${ext.toLowerCase()}`] = mimes_json[ext];
  }
  return ret;
}

/**
 * @param {String} conf_path 
 */
function parse_config(conf_path)
{
  let raw_conf = JSON.parse(fs.readFileSync(conf_path));
  let conf = {
    hosts: new Map()
  };

  if(!raw_conf['bin_path'])
  {
    console.error('PHP-CGI executable path undefined. Abort.');
    return;
  }
  let bin_path = raw_conf['bin_path'];
  if(!fs.existsSync(bin_path) || !fs.statSync(bin_path).isFile())
  {
    console.error('PHP-CGI executable is not executable. Abort.');
    return;
  }
  conf['bin_path'] = bin_path;

  if(raw_conf['https'])
  {
    conf['https'] = true;
    conf['httpsPort'] = raw_conf['httpsPort'] || 443;

    if(!raw_conf['fallbackHttpsPrivateKey'] || !raw_conf['fallbackHttpsCertificate'])
    {
      console.error('Default keypair must be specified for HTTPS server. Abort.');
      return;
    }
    conf['httpsPrivateKey'] = fs.readFileSync(raw_conf['fallbackHttpsPrivateKey']);
    conf['httpsCertificate'] = fs.readFileSync(raw_conf['fallbackHttpsCertificate']);

    if(raw_conf['httpSlave'])
    {
      conf['httpSlave'] = true;
      conf['httpPort'] = raw_conf['httpPort'] || 80;
    }
    else
    {
      conf['httpSlave'] = false;
    }
  }
  else
  {
    conf['https'] = false;
    conf['httpPort'] = raw_conf['httpPort'] || 80;
  }

  if(raw_conf['ini_dir'])
  {
    let ini_dir = path_is_absolute(raw_conf['ini_dir']) ? path.normalize(raw_conf['ini_dir']) : path.resolve(raw_conf['ini_dir']);
    if(fs.existsSync(ini_dir) && fs.statSync(ini_dir).isDirectory())
    {
      conf['ini_dir'] = ini_dir;
    }
    else
    {
      console.error('WARNING: Ignored invalid master INI path. You may want to take care of this to mitigate security risks.');
    }
  }

  if(!raw_conf['hosts'])
  {
    console.error('No hostname defined. Abort.');
    return;
  }
  for(let host_idx in raw_conf['hosts'])
  {
    let host_conf_raw = raw_conf['hosts'][host_idx];
    if(!host_conf_raw['domain'] || !host_conf_raw['web_root'])
    {
      console.error('Ignored invalid host entry.');
      continue;
    }

    let host_conf = {
      web_root: path_is_absolute(host_conf_raw['web_root']) ? path.normalize(host_conf_raw['web_root']) : path.resolve(host_conf_raw['web_root'])
    };
    conf.hosts.set(host_conf_raw['domain'].toLowerCase(), host_conf);

    // Set ini search directory for PHP.
    if(host_conf_raw['ini_dir'])
    {
      let ini_dir = path_is_absolute(host_conf_raw['ini_dir']) ? path.normalize(host_conf_raw['ini_dir']) : path.resolve(host_conf_raw['ini_dir']);
      if(fs.existsSync(ini_dir) && fs.statSync(ini_dir).isisDirectory())
      {
        host_conf['ini_dir'] = ini_dir;
      }
      else
      {
        console.error('Ignored invalid per-host INI path.');
      }
    }

    // Fallback handler override for directories or bad paths. Must be posix absolute path just like a request path!
    if(host_conf_raw['fallback_route'])
    {
      host_conf['fallback_route'] = path.posix.normalize(host_conf_raw['fallback_route']);
    }

    if(raw_conf['https'])
    {
      if(host_conf_raw['httpsPrivateKey'] && host_conf_raw['httpsCertificate'])
      {
        try
        {
          host_conf['ssl_ctx'] = tls.createSecureContext({
            key: fs.readFileSync(host_conf_raw['httpsPrivateKey']),
            cert: fs.readFileSync(host_conf_raw['httpsCertificate'])
          });
        }
        catch(err)
        {
          console.error(err);
          console.error('Ignored invalid host SSL keypairs.');
        }
      }
    }
  }

  if(raw_conf['tmp_dir'])
  {
    let tmp_dir = path.resolve(raw_conf['tmp_dir']);
    if(fs.existsSync(tmp_dir) && fs.statSync(tmp_dir).isDirectory())
    {
      conf['tmp_dir'] = tmp_dir;
    }
  }

  let err_pages = {};
  if(raw_conf['error_pages'])
  {
    for(let err_idx in raw_conf['error_pages'])
    {
      let err_page_raw = raw_conf['error_pages'][err_idx];
      if(!err_page_raw['code'] || !err_page_raw['path'])
      {
        console.error('Ignored invalid error page entry.');
        continue;
      }

      if(!fs.existsSync(err_page_raw['path']) || !fs.statSync(err_page_raw['path']).isFile())
      {
        console.error(`Cannot read error page content for code ${err_page_raw['code']}.`);
        continue;
      }

      err_pages[err_page_raw['code']] = fs.readFileSync(err_page_raw['path']);
    }
  }
  conf['error_pages'] = err_pages;

  conf['mimes'] = getMimeMap();

  return conf;
}

/**
 * 
 * @param {String[]} args 
 */
function __main__(args)
{
  setup_server(parse_config(`${__dirname}/config.json`));
}

__main__(process.argv.slice(2));
