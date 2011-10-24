<?php
error_reporting(E_ALL ^ E_NOTICE);

require './config.php';
require './function.php';
require './jsonRPCClient.php';
require './name.class.php';
 
$rpc = new jsonRPCClient($jsonConnect);
$name_scan = $rpc->name_scan("", 100000000);
#print_r($name_scan);
#$name_scan[] = array('name'=>'d/test','value'=>"{\"info\":{\"registrar\":\"http://register.dot-bit.org\"},\"map\": {\"\": \"46.137.88.107\", \"www\": \"46.137.88.107\"} }");
#$name_scan[] = array('name'=>'d/test','value'=>"{\"info\":{\"registrar\":\"http://register.dot-bit.org\"},\"dns\":[\"ns0.web-sweet-web.net\",\"ns1.web-sweet-web.net\"],\"map\":{\"\":{\"ns\":[\"ns0.web-sweet-web.net\",\"ns1.web-sweet-web.net\"]}}} ");

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

$backupDoms = @file_get_contents($cacheDir.'domains');

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
	$domains_list[] = $d->name;
	$domains[$d->name] = $d;

	unset($name_scan[$i]);
}
unset($name_scan);

// no change in list of valid names 
$backup = @file_get_contents($cacheDir.'names_list');
if($backup == md5(serialize($names_list))) {
	echo 'No change in list of valid names';
	exit;
}
file_put_contents2($cacheDir.'names_list', md5(serialize($names_list)));
if($statDir) { file_put_contents2($statDir.'domain_count.txt', count($names_list)); }
if($statDir) { file_put_contents2($statDir.'domain_list.txt', implode("\n",$names_list)); }
unset($names_list);

// no change in list of valid domains
$backup = @file_get_contents($cacheDir.'domains_list');
if($backup == md5(serialize($domains_list))) {
	echo 'No change in list of valid domains';
	exit;
}
file_put_contents2($cacheDir.'domains_list', md5(serialize($domains_list)));
unset($domains_list);
unset($backup);

// no change in content of list of valid domains
if($backupDoms == serialize($domains)) {
	echo 'No change in content of list of valid domains';
	exit;
}
file_put_contents2($cacheDir.'domains', serialize($domains));

ksort($domains);
$bitZones = array();
$bitForwards = array();
$backupDoms = unserialize($backupDoms);
$oldBind = unserialize(@file_get_contents($cacheDir.'bind_domains_list'));
foreach($domains as $name=>$dom) {
	// domain has changed
	#if($backupDoms[$name]->value['value'] != $dom->value['value']) {
	if($dom->hasValueChanged($backupDoms[$name]->value['value'])) {
		$dom->getBindZones();
		if(count($dom->bindZones)) {
			$newBind['zones'][$name] = (array)$dom->bindZones;
			$oldBind['zoneslist'][$name] = array_keys((array)$dom->bindZones);
		} else {
			if(isset($oldBind['zoneslist'][$name])) { unset($oldBind['zoneslist'][$name]); $todoZones = true; }
		}
		if(count($dom->bindForwards)) {
			$newBind['forwards'][$name] = (array)$dom->bindForwards;
			$oldBind['forwards'][$name] = (array)$dom->bindForwards;
		} else {
			if(isset($oldBind['forward'][$name])) { unset($oldBind['forward'][$name]); $todoForwards = true; }
		}
	} else {
		unset($domains[$name]);
		unset($backupDoms[$name]);
	}

}
unset($domains);
unset($backupDoms);
file_put_contents2($cacheDir.'bind_domains_list', serialize($oldBind));

#echo '<pre>Zones : '; print_r($newBind['zones']); echo '</pre>';
#echo '<pre>Zones : '; print_r($oldBind['zoneslist']); echo '</pre>';
#echo '<pre>Forwards : '; print_r($newBind['forwards']); echo '</pre>';

// generate list of forwarded domains
if($todoForwards || count($newBind['forwards'])) {
	$bitForward = '';
	foreach($oldBind['forwards'] as $name) {
		foreach($name as $domain=>$ns) {
			$bitForward .= 'zone "'.$domain.'" { type forward; forwarders { '.implode("; ", $ns).'; }; };'."\n";
		}
	}
	#echo '<pre>Forwards :'."\n".$bitForward.'</pre>';
	file_put_contents2($bindZonesList.'bit-forward.conf', $bitForward);
}

// generate list of master domains
if($todoZones || count($newBind['zones'])) {
	$bitMaster = '';
	foreach($oldBind['zoneslist'] as $name) {
		foreach($name as $domain=>$zone) {
			$bitMaster .= 'zone "'.$zone.'" { type master; file "'.$bindZonesFiles.$zone.'"; allow-query { any; }; };'."\n";
		}
	}
	#echo '<pre>Masters :'."\n".$bitMaster.'</pre>';
	file_put_contents2($bindZonesList.'bit-master.conf', $bitMaster);
}

// generate new zones
foreach((array)$newBind['zones'] as $name) {
	foreach($name as $domain=>$zone) {
		$template = file_get_contents(dirname(__FILE__).'/zone-template.conf');
		$template = str_replace('@@DOMAINE@@', $domain, $template);
		#$template = str_replace('%%serial%%', '1', $template);
		$template = str_replace('%%authns%%', $authoritativeNS[0], $template);
		$template = str_replace('%%email%%', isset($zone['email']) ? str_replace('@', '.', $zone['email']) : 'hostmaster.'.$domain, $template);
		unset($zone['email']);
		$template = str_replace('%%serial%%', date('YmdHi'), $template);
		if($authoritativeNS[0]) {	$template .= "         IN  NS       ".$authoritativeNS[0].".\n";	}
		if($authoritativeNS[1]) {	$template .= "         IN  NS       ".$authoritativeNS[1].".\n";	}
		foreach($zone as $record) {
			$template .= $record."\n";
		}
		#$template = str_replace('%%mx%%', $ip, $template);
		file_put_contents2($bindZonesFiles.$domain, $template);
		#echo '<pre>Zone '.$domain.' :'."\n".$template.'</pre>';
	}
}

#echo '<br />'; echo memory_get_usage(); echo '<br />'; echo memory_get_usage(true);

function file_put_contents2($file, $data) {
	global $doFileWrites;
	if($doFileWrites) {
		file_put_contents($file, $data);
	}
	echo "Write : $file<br />";
}

?>
