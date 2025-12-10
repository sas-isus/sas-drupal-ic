<?php

if (file_exists(__DIR__ . '/settings.sas-functions.php')) {
    require_once __DIR__ . "/settings.sas-functions.php";
}

/*
 * Use _ENV not _SERVER - https://pantheon.io/docs/read-environment-config/
 *
 */

if (isset($_ENV['PANTHEON_ENVIRONMENT']) && php_sapi_name() != 'cli') {
 
	// Ensure we're on https
	if (isHTTP()) {
		$NewURL = 'https://' . $_SERVER['HTTP_HOST'];
		if (isset($_SERVER['REQUEST_URI'])) {
			$NewURL = $NewURL . $_SERVER['REQUEST_URI'];
		}

		redirectTo($NewURL);
	}

    	// keep any drupal_hash_salt we set in setting.php or other files
   	if (isset($drupal_hash_salt)) {
       		$pf = json_decode($_SERVER['PRESSFLOW_SETTINGS']);
       		$pf->drupal_hash_salt = $drupal_hash_salt;
        	$_SERVER['PRESSFLOW_SETTINGS'] = json_encode($pf);
    	}


	// redirect to BaseURL unless we're being proxied or we're on a pantheon site -- The proxy is supposed to handle redirections
	// Never let this redirect be cached in case we're proxied at some point -- just don't do it.
	$CanonicalHost = getCanonicalHost();

	$CurrentHost = $_SERVER['HTTP_HOST'];
	if (!isProxied() && !isPantheonSite() && isset($CanonicalHost) && $CurrentHost != $CanonicalHost) {
		if (isset( $_SERVER['REQUEST_URL'])) {
			$RequestURI = $_SERVER['REQUEST_URL'];
		}
		else {
			$RequestURI = "/";
		}

		$NewURL = 'https://' . $CanonicalHost . $RequestURL;
		redirectTo($NewURL, False);
	}
}

#
# Set the simplesaml directory path for d7, d8 and d8-refactored sites.
#
# This could be pulled out and redone by each repo, or just cherry pick the code here.
#
# From https://pantheon.io/docs/shibboleth-sso/
#  D7: $conf['simplesamlphp_auth_installdir'] = $_ENV['HOME'] .'/code/private/simplesamlphp';
#  D8-upstream: $settings['simplesamlphp_dir'] = $_ENV['HOME'] .'/code/private/simplesamlphp';
#  D8-refactored: $settings['simplesamlphp_dir'] = $_ENV['HOME'] .'/code/web/private/simplesamlphp';
#
if (isset($_ENV['HOME'])) {
	if (isD8()) {
		if (file_exists($_ENV['HOME'] . '/code/vendor/simplesamlphp/simplesamlphp/www/index.php')) {
			$settings['simplesamlphp_dir'] = $_ENV['HOME'] . '/code/vendor/simplesamlphp/simplesamlphp';
		}
	}
	else {
		$conf['simplesamlphp_auth_installdir'] = $_ENV['HOME'] . '/code/private/simplesamlphp';
	}
}

#
# Deal with site specific recdirects
#
if (isset($RewriteMap) && (isset($_SERVER['argv'][1]) || isset($_SERVER['REQUEST_URI']))) {
    #
    # run as:
    # php settings.redirects-allsites.php /uniconn
    # to see the redirects for each url
    #

    $oldurl = (php_sapi_name() == "cli") ? $_SERVER['argv'][1] : $_SERVER['REQUEST_URI'];

    foreach ($RewriteMap as $key => $value) {
        if (preg_match($key, $oldurl)) {
            $newurl = preg_replace($key,$value,$oldurl);
            if (isset($_ENV['PANTHEON_ENVIRONMENT'])) {
		redirectTo($newurl);
            }
            else {
                print("$oldurl => $newurl\n");
            }

            exit();
        }
    }
}


// block a list of bots using user agent
$user_agents_deny_list = ['Go-http-client', 'gozilla', 'InstallShield.DigitalWizard', 'GT\:\:WWW', 'brightbot', 'Pingdom','Brightbot 1.0','Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)', 'serpstatbot', 'Go-http-client/1.1'];
foreach ($user_agents_deny_list as $agent) {
  if (strpos($_SERVER['HTTP_USER_AGENT'], $agent) !== FALSE) {
    header('HTTP/1.0 403 Forbidden');
    exit;
  }
}
/* Block aggressive bots ignoring robots.txt */
$request_ip_blocklist = [
  '82.97.199.0/30',
  '61.0.3163.79',
  '64.227.159.0/30',
  '148.72.171.0/30',
  #'52.169.201.215/30',
  '14.215.51.70/30',
  '14.215.51.70/30',
  '92.62.121.70/30',
  '82.97.199.0/30',
  '183.162.122.116/30',
  '36.148.178.240/30',
 # '52.42.92.117/30',
  '167.172.83.1/30',
  '3.82.25.219/30',
  '188.166.178.229/30',
 # '52.4.143.42/30',
#  '180.149.13.97',
#  '206.204.57.251',
#  '76.32.215.122',
  '185.152.65.167/30',
  '185.246.208.0/30',
  '152.39.197.201',
  '152.39.168.0/30',
#  '191.177.139.6',
#  '52.167.144.0/30',
  '154.16.169.92/30',
  '40.69.216.119',
  '34.174.140.184',
  '45.134.225.130',
  '10.1.66.0/30',
  '46.250.238.31',
  '45.134.225.130',
  '34.174.37.178',
  '81.209.177.145',
  '167.172.85.98',
  '13.76.77.155',
  '217.195.155.34',
  '43.134.54.97'
];

$conf['restrict_ip_whitelist'] = array(
        '52.42.92.117',
        '130.91.210.230',
        '130.91.210.231',
        '54.188.22.153'
);

$request_remote_addr = $_SERVER['REMOTE_ADDR'];
// Check if this IP is in blocklist.
if (!$request_ip_forbidden = in_array($request_remote_addr, $request_ip_blocklist)) {
  // Check if this IP is in CIDR block list.
  foreach ($request_ip_blocklist as $_cidr) {
    if (strpos($_cidr, '/') !== FALSE) {
      $_ip = ip2long($request_remote_addr);
      list ($_net, $_mask) = explode('/', $_cidr, 2);
      $_ip_net = ip2long($_net);
      $_ip_mask = ~((1 << (32 - $_mask)) - 1);

      if ($request_ip_forbidden = ($_ip & $_ip_mask) == ($_ip_net & $_ip_mask)) {
        break;
      }
    }
  }
}

if ($request_ip_forbidden) {
  header('HTTP/1.0 403 Forbidden');
  exit;
}
 
