<?php
$startTime = microtime(true);
if (PHP_SAPI != 'cli') {
	ob_start();
}

require __DIR__.'/config.php';
require __DIR__.'/function.php';
require __DIR__.'/jsonRPCClient.php';
require __DIR__.'/name.class.php';

if(isset($showDebug) && $showDebug) {
	error_reporting(E_ALL ^ E_NOTICE);
	ini_set('display_errors','On');
}
ini_set('memory_limit', 200*1024*1024);

//
$rpc = new jsonRPCClient($jsonConnect);
try {
	$getinfo = $rpc->getinfo();
} catch (Exception $e) {
	sleep(10);
	$getinfo = $rpc->getinfo();
}
if(!$getinfo_old = get_cache('getinfo')) {
	$getinfo_old = array('blocks' => 0);
}
if($getinfo['blocks'] == $getinfo_old['blocks']) {
	echo 'Still on same block'; exit;
}
echo "New blocks : ".($getinfo['blocks'] - $getinfo_old['blocks'])."\n";
showDebug(0);


//
$diff = $getinfo['blocks'] - $getinfo_old['blocks'];
$new_names = $rpc->name_filter("^d/[a-z0-9_-]+$", $diff);
#echo '<pre>'; print_r($new_names);
if(!count($new_names)) {
	echo 'No new name since last scan'; exit;
}
showDebug(1);


// there are new names
echo "New names : ".count($new_names)."\n";
format_names($new_names, $getinfo['blocks']);
#echo '<pre>'; print_r($new_names);
set_cache('getinfo', $getinfo);

// get list of names block
if(!$names_block = get_cache('names_block'))
	$names_block = array();
if(!$bind_tree = get_cache('bind_tree'))
	$bind_tree = array();

// remove expired names
foreach($names_block as $name => $block) {
	if($block < $getinfo['blocks']) {
		if(isset($showDebug) && $showDebug) echo 'Expired : '.$name.' ('.$block.')'."\n";
		unset($names_block[$name]);
		unset($bind_tree[$name]);
	}
}
showDebug(2);


// add new names
$nb_new_names = 0;
foreach($new_names as $name) {
	// domain has a non ascii name
	if(!dom::isNameValid($name['name'])) {
		if(isset($showErrors) && $showErrors) echo 'Not a valid name : '.$name['name']."\n";
		continue;
	}

	// domain has an invalid json value
	$dom = new dom($name['name'], $name);
	if(isset($name['value']) && !$dom->isValueJson($name['value'])) {
		continue;
	}

	// convert data to bind
	$dom->getBindZones();
	if(isset($dom->bindForwards) && count($dom->bindForwards)) {
		$names_block[$name['name']] = $name['expire'];
		$bind_tree[$name['name']] = (array)$dom->bindForwards;
		$nb_new_names++;
	}
}
if(!$nb_new_names) {
	echo 'No new bind domain'; exit;
}
echo "New domains : ".($nb_new_names)."\n";
set_cache('names_block', $names_block);
set_cache('bind_tree', $bind_tree);
#echo '<pre>'; print_r($bind_tree);
showDebug(3);


// prepare bind zones
foreach($bind_tree as $id => $tree)
		$bind_tree[$id] = implode("\n", $tree);
$bind_zones = implode("\n", $bind_tree);
#echo '<pre>'.$bind_zones;
showDebug(4);


// generate root zone
$filename = file_exists($templateFile) ? $templateFile : dirname(__FILE__).'/zone-template.conf';;
$template = file_get_contents($filename);
$template = str_replace('@@DOMAINE@@', 'bit', $template);
#$template = str_replace('%%serial%%', '1', $template);
$template = str_replace('%%authns%%', $authoritativeNS[0][0], $template);
$template = str_replace('%%email%%', 'hostmaster.'.$authoritativeNS[0][0], $template);
$template = str_replace('%%serial%%', time()-1303087979, $template);
foreach($authoritativeNS as $i => $ns) {
	$template .= "	  IN NS   ".$authoritativeNS[$i][0].".\n";
	foreach((array)$authoritativeNS[$i][1] as $ip) {
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			$template .= $authoritativeNS[$i][0].".  IN AAAA ".$ip."\n";
		} elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$template .= $authoritativeNS[$i][0].".  IN A	".$ip."\n";
		}
	}
}
$template .= "\n".$bind_zones."\n\n";
#echo '<pre>'.$template;
file_put_contents2($bindZonesList.'db.namecoin.bit', $template);
showDebug(5);


// write stats
if($statDir) {
	try {
		$res = $rpc->name_filter("", 0, 0, 0, "stat");
		file_put_contents2($statDir.'name_count.txt', $res['count']);
		echo 'NB names : '.$res['count']."\n";

		$res = $rpc->name_filter("^d/", 0, 0, 0, "stat");
		file_put_contents2($statDir.'domain_count.txt', $res['count']);
		echo 'NB domains : '.$res['count']."\n";

		file_put_contents2($statDir.'domain_bind_count.txt', count($bind_tree));
		echo 'NB bind zones : '.count($bind_tree)."\n";
	} catch(Exception $e) {}
}
showDebug(6);




function file_put_contents2($file, $data) {
	global $doFileWrites;
	if($doFileWrites) {
		file_put_contents($file, $data);
	}
	echo "Write : $file\n";
}

function cache_getfilename($file, $func = 'seri') {
	global $cacheDir;
	return $cacheDir.basename($file).'_'.$func;
}

function get_cache($file, $func = 'seri') {
	$file = cache_getfilename($file, $func);
	if(!file_exists($file)) 
		return false;
	if($func == 'md5') {
		$data = md5(@file_get_contents($file));
	} elseif($func == 'json') {
		$data = json_decode(@file_get_contents($file));
	} elseif($func == 'seri') {
		$data = unserialize(@file_get_contents($file));
	}
	return $data;
}

function set_cache($file, $data, $func = 'seri') {
	$file = cache_getfilename($file, $func);
	if($func == 'md5') {
		file_put_contents2($file, md5(json_encode($data)));
	} elseif($func == 'json') {
		file_put_contents2($file, json_encode($data));
	} elseif($func == 'seri') {
		file_put_contents2($file, serialize($data));
	}
}

function del_cache($file, $func = 'seri') {
	$file = cache_getfilename($file, $func);
	unlink($file);
}

function cache_changed($file, $data, $func = 'seri') {
	$file = cache_getfilename($file, $func);
	$backup = @file_get_contents($file);
	if($func == 'md5') {
		if($backup != md5(json_encode($data))) {
			file_put_contents2($file, md5(json_encode($data)));
			return true;
		}
	} elseif($func == 'json') {
		if($backup != json_encode($data)) {
			file_put_contents2($file, json_encode($data));
			return true;
		}
	} elseif($func == 'seri') {
		if($backup != serialize($data)) {
			file_put_contents2($file, serialize($data));
			return true;
		}
	}
	return false;
}

function format_names(&$names, $block) {
	foreach($names as $id => $name) {
		if (isset($names[$id]['expired'])) {
			unset($names[$id]);
		} else {
			$names[$id]['expire'] = $block + $names[$id]['expires_in'];
			unset($names[$id]['expires_in']);
		}
	}
}

function showDebug($txt) {
	global $showDebug, $startTime;
	if(!isset($showDebug) || !$showDebug) return;
	echo "\n<b>* ".$txt.' :</b> ';
	echo number_format(memory_get_usage()/1024/1024, 1, '.', "'");
	echo 'MB (';
	echo number_format(memory_get_usage(true)/1024/1024, 1, '.', "'");
	echo 'MB) - ';
	echo number_format(microtime(true) - $startTime, 2, '.', "'").'s';
	echo "\n";
	flush();
}

showDebug(10);

if (PHP_SAPI != 'cli') {
	$buffer = ob_get_clean();
	echo nl2br($buffer);
}
?>
