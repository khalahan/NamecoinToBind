<?php
error_reporting(E_ALL ^ E_NOTICE);

require './config.php';
require './function.php';
require './jsonRPCClient.php';
require './name.class.php';
 
$rpc = new jsonRPCClient($jsonConnect);
#$name_scan = $rpc->name_scan("", 10000);
$name_scan = $rpc->name_scan("", 10000000);
#print_r($name_scan);
#$name_scan[] = array('name'=>'d/test5','value'=>"{\"info\":{\"registrar\":\"http://register.dot-bit.org\"},\"map\": {\"\": \"46.137.88.107\", \"www\": \"46.137.88.107\"} }");
#$name_scan[] = array('name'=>'d/test5','value'=>"{\"info\":{\"registrar\":\"http://register.dot-bit.org\"},\"dns\":[\"ns0.web-sweet-web.net\",\"ns1.web-sweet-web.net\"],\"map\":{\"\":{\"ns\":[\"ns0.web-sweet-web.net\",\"ns1.web-sweet-web.net\"]}}} ");
#$name_scan[] = array('name'=>'d/test5','value'=>"{\"map\": {\"\": {\"ns\": [\"193.17.184.183\"]}}} ");

// Exit if bad data
if(!count($name_scan) && !isset($name_scan[0]['name'])) {
	echo 'No data';
	exit;
}

// no change in name_scan
$backup = @file_get_contents($cacheDir.'name_scan');
if($backup == md5(serialize($name_scan))) {
	echo 'No change in name_scan';
	exit;
}
file_put_contents2($cacheDir.'name_scan', md5(serialize($name_scan)));
unset($backup);
if($statDir) { file_put_contents2($statDir.'name_count.txt', count($name_scan)); }
if($statDir) {
	$tmp = array();
	foreach($name_scan as $id=>$dom) { $tmp[] = $dom['name']; }
	sort($tmp);
	file_put_contents2($statDir.'name_list.txt', implode("\n",$tmp));
	unset($tmp);
}

// filter bad names and domains
foreach($name_scan as $id=>$dom) {
	// domain has a non ascii name
	$d = new dom($dom['name'], $dom);
	if(!$d->isNameValid()) {
		if($showErrors) echo $d->errors().' : '.$d->name.'<br />';
		continue;
	}
	// list of valid names
	$names_list[] = $d->name;

	// domain has an invalid json value
	if(!$d->isValueJson()) {
		if($showErrors) echo $d->errors().' : '.$d->name.'<br />';
		#if($showErrors) echo '<pre>'; print_r($d->json); echo '</pre>';
		continue;
	}
	// list of valid domains
	$domains[$d->name] = $d;

	unset($name_scan[$i]);
}
unset($name_scan);

if($statDir) { file_put_contents2($statDir.'domain_count.txt', count($names_list)); }
if($statDir) { file_put_contents2($statDir.'domain_list.txt', implode("\n",$names_list)); }
unset($names_list);

// no change in content of valid domains
$backup = @file_get_contents($cacheDir.'domains_md5');
if($backup == md5(serialize($domains))) {
	echo 'No change in content of valid domains';
	exit;
}
file_put_contents2($cacheDir.'domains_md5', md5(serialize($domains)));

ksort($domains);
$bind = unserialize(@file_get_contents($cacheDir.'bind'));
$backupDoms = unserialize(@file_get_contents($cacheDir.'domains'));
foreach($domains as $name=>$dom) {
	// domain has changed
	if($dom->hasValueChanged($backupDoms[$name]->value['value'])) {
		if(isset($bind['zonesnew'][$name]))
			unset($bind['zonesnew'][$name]);
		if(isset($bind['zoneslist'][$name]))
			unset($bind['zoneslist'][$name]);
		if(isset($bind['forwards'][$name]))
			unset($bind['forwards'][$name]);
		$dom->getBindZones();
		if(count($dom->bindZones)) {
			$bind['zonesnew'][$name] = (array)$dom->bindZones;
			$bind['zoneslist'][$name] = array_keys((array)$dom->bindZones);
		}
		if(count($dom->bindForwards)) {
			$bind['forwards'][$name] = (array)$dom->bindForwards;
		}
	}

}
file_put_contents2($cacheDir.'domains', serialize($domains));
unset($domains);
unset($backupDoms);

#echo '<pre>Zones : '; print_r($bind['zonesnew']); echo '</pre>';
#echo '<pre>Zones : '; print_r($bind['zoneslist']); echo '</pre>';
#echo '<pre>Forwards : '; print_r($bind['forwards']); echo '</pre>';


/*$backup = @file_get_contents($cacheDir.'forward_list');
if($backup != md5(serialize($bind['forwards']))) {
	file_put_contents2($cacheDir.'forward_list', md5(serialize($bind['forwards'])));
}*/
// generate list of forwarded domains
	#$bitForward = '';
	foreach($bind['forwards'] as $name) {
		foreach($name as $domain=>$ns) {
			#$bitForward .= 'zone "'.$domain.'" { type forward; forwarders { '.implode("; ", $ns).'; }; };'."\n";
			foreach($ns as $n) {
				$n = preg_replace('@[^a-zA-Z0-9_.-]@', '', $n);
				if(filter_var($n, FILTER_VALIDATE_IP)) {
					$bitRoot .= str_replace('.bit', '', $domain)."	IN NS	".str_replace('.bit', '', $domain).".ns\n";
					if(filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
						$bitRoot .= str_replace('.bit', '', $domain).".ns	IN A	".$n."\n";
					} elseif(filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
						$bitRoot .= str_replace('.bit', '', $domain).".ns	IN AAAA	".$n."\n";
					}
				} else {
					$bitRoot .= str_replace('.bit', '', $domain)."	IN NS	".$n.(substr($n, -1) == '.' ? '' : '.')."\n";
				}
			}
		}
	}
	$bitRoot .= "\n";
	#echo '<pre>Forwards :'."\n".$bitForward.'</pre>';
	#file_put_contents2($bindZonesList.'bit-forward.conf', $bitForward);


$backup = @file_get_contents($cacheDir.'zone_list');
if($backup != md5(serialize($bind['zoneslist']))) {
	file_put_contents2($cacheDir.'zone_list', md5(serialize($bind['zoneslist'])));
}
// generate list of master domains
	$bitMaster = '';
	foreach($bind['zoneslist'] as $name) {
		foreach($name as $domain=>$zone) {
			$ext = pathinfo($zone, PATHINFO_EXTENSION);
			$dom = preg_replace('@'.$ext.'$@', '', pathinfo($zone, PATHINFO_BASENAME));
			$bitMaster .= 'zone "'.$dom.$ext.'" { type master; file "'.$bindZonesFiles.$zone.'"; allow-query { any; }; };'."\n";

			foreach($authoritativeNS as $ns) {
				$bitRoot .= str_replace('.bit', '', $zone)."	IN NS	".$ns[0].(substr($n, -1) == '.' ? '' : '.')."\n";
			}
		}
	}
	#echo '<pre>Masters :'."\n".$bitMaster.'</pre>';
	file_put_contents2($bindZonesList.'zones-master.conf', $bitMaster);


	// generate root zone
	$template = file_get_contents(dirname(__FILE__).'/zone-template.conf');
	$template = str_replace('@@DOMAINE@@', 'bit', $template);
	#$template = str_replace('%%serial%%', '1', $template);
	$template = str_replace('%%authns%%', $authoritativeNS[0][0], $template);
	$template = str_replace('%%email%%', 'hostmaster.'.$authoritativeNS[0][0], $template);
	$template = str_replace('%%serial%%', date('YmdHi'), $template);
	$template .= "		IN NS	".$authoritativeNS[0][0].".\n";
	$template .= $authoritativeNS[0][0].".	IN A	".$authoritativeNS[0][1]."\n";
	#$template .= "		IN NS	gluens\n";
	#$template .= "gluens	IN A	".$authoritativeNS[0][1]."\n";
	$template .= "\n".$bitRoot;
	file_put_contents2($bindZonesList.'root-bit.zone', $template);
	#echo '<pre>bitRoot :<br />'; print_r($bitRoot); echo '</pre>';
	#echo '<pre>bitRoot :<br />'; print_r($template); echo '</pre>';

// generate new zones
foreach((array)$bind['zonesnew'] as $name) {
	foreach($name as $domain=>$zone) {
		$template = file_get_contents(dirname(__FILE__).'/zone-template.conf');
		$template = str_replace('@@DOMAINE@@', $domain, $template);
		#$template = str_replace('%%serial%%', '1', $template);
		$template = str_replace('%%authns%%', $authoritativeNS[0][0], $template);
		$template = str_replace('%%email%%', isset($zone['email']) ? str_replace('@', '.', $zone['email']) : 'hostmaster.'.$domain, $template);
		unset($zone['email']);
		$template = str_replace('%%serial%%', date('YmdHi'), $template);
		$template .= "		IN NS	".$authoritativeNS[0][0].".\n";
		#$template .= $authoritativeNS[0][0].".	IN A	".$authoritativeNS[0][1]."\n";
		#$template .= "		IN NS	masterns\n";
		#$template .= "masterns	IN A	".$authoritativeNS[0][1]."\n";
		#if($authoritativeNS[0]) {	$template .= "         IN  NS       ".$authoritativeNS[0].".\n";	}
		#if($authoritativeNS[1]) {	$template .= "         IN  NS       ".$authoritativeNS[1].".\n";	}
		foreach($zone as $record) {
			$template .= $record."\n";
		}
		#$template = str_replace('%%mx%%', $ip, $template);
		file_put_contents2($bindZonesFiles.$domain, $template);
		#echo '<pre>Zone '.$domain.' :'."\n".$template.'</pre>';
	}
}
unset($bind['zonesnew']);
file_put_contents2($cacheDir.'bind', serialize($bind));

function file_put_contents2($file, $data) {
	global $doFileWrites;
	if($doFileWrites) {
		file_put_contents($file, $data);
	}
	echo "Write : $file<br />";
}

#echo '<br />'; echo memory_get_usage(); echo '<br />'; echo memory_get_usage(true);

?>
