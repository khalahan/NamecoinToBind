<?php
error_reporting(E_ALL ^ E_NOTICE);

require './function.php';
require './jsonRPCClient.php';
 
$namecoin = new jsonRPCClient('http://user:pass@127.0.0.1:8336/');
$domains = $namecoin->name_scan("", 100000000);

$infos = $namecoin->getinfo();
file_put_contents('./q/blocknumber.txt', $infos['blocks']);

#print_r($domains);
#$domains[] = array('name'=>'d/xn--t4c', 'value'=>'{"map": {"": {"ns": ["ns0.web-sweet-web.net", "ns1.web-sweet-web.net"]}}}');
#$domains[] = array('name'=>'d/opennic', 'value'=>'{"map": {"": {"ns": ["ns0.web-sweet-web.net", "ns1.web-sweet-web.net"]}}}');
#$domains[] = array('name'=>'d/testx', 'value'=>'{"map": {"": "78.47.86.43", "www": {"ns": ["200.200.219.3", "200.200.219.2"]}}}');
#$domains[] = array('name'=>'d/testnic2', 'value'=>'{"map": {"": "78.47.86.43", "www": "200.200.219.3"}}');

// get domains to update
echo '<pre>';
$backup = unserialize(@file_get_contents('./cache/namescan_map'));
#print_r($backup);
foreach($domains as $id=>$dom) {
	if(!preg_match('@^d/[\x00-\x7F]+$@', $dom['name'])) {
		echo "BAD name: ".$dom['name'].'<br />';
		unset($domains[$id]);
		continue;
	}

	/*$out = array();
	exec("LANG=en_US.UTF-8 /usr/bin/idn --allow-unassigned --usestd3asciirules --profile=Nameprep --idna-to-unicode '".substr($dom['name'], 2)."'", $out);
	if(count($out)) {
		print_r($out);
		echo '<br />';
	} else {
		print_r($dom);
		echo "BAD: ".substr($dom['name'], 2).'<br />';
	}
	if(!count($out)) {
		#unset($domains[$id]);
		#continue;
	}*/
	
	#$domains[$id]['name'] = $dom['name'] = 'd/'.strtolower($IDN->encode(substr($dom['name'], 2)));
	$namescan_list[] = $dom['name'];

	// patch json single quote
	if(preg_match("@{'map':@", $dom['value'])) {
		$domains[$id]['value'] = $dom['value'] = str_replace("'", '"', $dom['value']);
	}
	$value = json_decode($dom['value']);
	if(isset($value->map)) {
		if($backup[$id] != $dom) {
			#echo $dom['name'].' - '.$dom['value'].'<br />';
			$update[$dom['name']] = $dom;
		}
	} else {
		unset($domains[$id]);
	}
}
if($backup != $domains) {
	file_put_contents('./cache/namescan_map', serialize($domains));
	file_put_contents('./cache/namescan_list', serialize($namescan_list));
	file_put_contents('./q/domainnumber.txt', count($namescan_list));
	file_put_contents('./q/domainlist.txt', implode("\n", $namescan_list));
} else {
	#exit;
}
#print_r($update);

// format data
$formatted = array();
$ipMask = '@[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}@';
$ns = array();
$hosts = array();
foreach($domains as $dom) {
	if($dom['expires_in'] > 0) {
		#echo $dom['name'].'<br />';
		$value = json_decode($dom['value']);
		if(isset($value->map))
		foreach($value->map as $id=>$value) {
			if($value) {
				// ns delegation
				if($value->ns) {
					#print_r($value);
					/*if(strpos($value->ns[0], ',') !== FALSE && count($value->ns) == 1) {
						$value->ns[0] = str_replace(' ', '', $value->ns[0]);
						$value->ns = explode(',', $value->ns[0]);
					}*/
					foreach($value->ns as $i=>$n) {
						if(!preg_match($ipMask, $n)) {
							#print_r(gethostbyname($n));
							$value->ns[$i] = gethostbyname($n);
						}
						if(!preg_match($ipMask, $value->ns[$i])) {
							unset($value->ns[$i]);
						}
					}
					if(count($value->ns)) {
						$formatted[$dom['name']]['ns'][$id] = $value->ns;
						$ns[($id!="_empty_"?$id.".":"").substr($dom['name'], 2).".bit"] = $value->ns;
					}
				// single ip
				} elseif (!isset($value->ns) && !is_object($value) && preg_match($ipMask, $value)) {
					#print_r($value);
					$formatted[$dom['name']]['host'][$id] = $value;
					$hosts[] = $value."	".($id!="_empty_"?$id.".":"").substr($dom['name'], 2).".bit";
				}
				// unknow
				else {
					#echo 'Unknown value type: '; print_r($value); echo "\n";
				}
			}
		}
	}
}


#echo '<pre>'; print_r($formatted); echo '<br />';
/*print_r($hosts);
echo '<br />';
print_r($ns);
echo '<br />';*/

if(@file_get_contents('./cache/bit-forward') != serialize($ns)) {
	file_put_contents('./cache/bit-forward', serialize($ns));

	$bitForward = '';
	foreach($formatted as $domain=>$val) {
		if(isset($val['ns'])) {
			$ns = $val['ns'];
			preg_match('@^([^/])+/(.+)$@', $domain, $parts);
			$domain = $parts[2];
			$domain .= '.bit';
			foreach($ns as $id=>$ns) {
				$sub = ($id == '_empty_' ? '' : $id.'.');
				$bitForward .= 'zone "'.$sub.$domain.'" { type forward; forwarders { '.implode("; ", $ns).'; }; };'."\n";
				unset($formatted[$domain]['host'][$id]);
			}
		}
	}
	#echo $bitForward;
	file_put_contents('/etc/bind/namecoin/bit-forward.conf', $bitForward);
}

if(@file_get_contents('./cache/bit-domains') != serialize($hosts)) {
	file_put_contents('./cache/bit-domains', serialize($hosts));

	$bitDomains = '';
	foreach($formatted as $domain=>$val) {
		if(isset($val['host'])) {
			$hosts = $val['host'];
			preg_match('@^([^/])+/(.+)$@', $domain, $parts);
			$domain = $parts[2];
			$domain .= '.bit';
			$bitDomains .= 'zone "'.$domain.'" { type master; file "/etc/bind/namecoin/'.$domain.'"; allow-query { any; }; };'."\n";

			$template = file_get_contents('/etc/bind/namecoin/bit-template.conf');
			$template = str_replace('@@DOMAINE@@', $domain, $template);
			#$template = str_replace('%%serial%%', '1', $template);
			$template = str_replace('%%serial%%', date('YmdHi'), $template);
			$template = str_replace('%%fqdn%%', 'dot-bit.org', $template);
			$template = str_replace('%%ns1%%', $ip, $template);
			$template = str_replace('%%ns2%%', $ip, $template);
			$template = str_replace('%%mx%%', $ip, $template);
			$records = '';
			foreach($hosts as $sub=>$ip) {
				if($sub == '_empty_') {
					$records .= str_pad('@', 8).'IN  A   '.$ip."\n";
					$records .= str_pad('*', 8).'IN  A   '.$ip."\n";
				} else {
					$records .= str_pad($sub, 8).'IN  A   '.$ip."\n";
				}
			}
			$template = str_replace('%%records%%', $records, $template);
			#echo $template;
			if(@file_get_contents('/etc/bind/namecoin/'.$domain) != $template) {
				#echo 'update zone : '.$domain.'<br />';
				file_put_contents('/etc/bind/namecoin/'.$domain, $template);
			}
		}
	}
	#echo $bitDomains;
	if(@file_get_contents('/etc/bind/namecoin/bit-domains.conf') != $bitDomains) {
		file_put_contents('/etc/bind/namecoin/bit-domains.conf', $bitDomains);
	}
}

?>
