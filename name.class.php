<?php

class name {
	public $name = null;
	public $value = null;
	public $json = null;
	public $errors = null;

	private $hasChanged = null;

	public function __construct($name = '', $value = '') {
		$this->name = $name;
		$this->value = $value;
	}

	public function errors() {
		return implode(', ',$this->errors);
	}

	public function hasValueChanged($value = '') {
		if($this->hasChanged == null) {
			$this->hasChanged = ($value != $this->value['value']);
		}

		return $this->hasChanged;
	}
}

class dom extends name {
	public function __construct($name = '', $value = '') {
		// patch json single quote
		if(isset($value['value']) && preg_match("@{'map':@", $value['value'])) {
			$value['value'] = str_replace("'", '"', $value['value']);
		}
		parent::__construct($name, $value);
	}

	public function isNameValid($name = '') {
		if(isset($this))
			$name = $name ? $name : $this->name;

		if(!preg_match('@^[d]/@', $name)) {
			if(isset($this)) $this->errors[] = 'Not in the domain namespace';
			return false;
		}
		
		if(!preg_match('@^[^/]+/[a-z0-9_-]+$@', $name)) {
			if(isset($this)) $this->errors[] = 'Not an ascii idn name';
			return false;
		}
		return true;
	}

	public function getDomainName($name = '') {
		return substr($this->value['name'], 2).'.bit';
	}

	public function getSubDomainName($name = '') {
		return substr($this->value['name'], 2);
	}

	public function getUnicodeName($name = '') {
		$name = $name ? $name : $this->name;
		if($name = idna_to_unicode($name)) {
			return $name;
		} else {
			$this->errors[] = 'Not a valid idn name';
			return false;
		}
	}

	public function isValueJson($value = '') {
		#var_dump(get_class($this));
		$value = $value ? $value : (isset($this->value['value']) ? $this->value['value'] : NULL);
		$value = json_decode($value);
		if(!is_null($value)) {
			$this->json = $value;
			return true;
		} else {
			$this->errors[] = 'Invalid JSON value';
			return false;
		}
	}

	private function cleanBadRecords($data) {
		$recordsTypesPriority = array(
			'delegate',
			'import',
			'ns',
			'dns',
			'translate',
			'alias',
			'map',
			);

		#foreach((array)$data as $recordType=>$recordValue) {
		foreach($recordsTypesPriority as $recordType) {
			#echo "RECORD: ".$recordType."<br />";
			if(!isset($data->$recordType)) continue;
			switch((string)$recordType){
			case 'delegate':	// Delegates control of this domain to the given Namecoin name, or a sub-domain entry defined within that name. All other entries are ignored.
				# "delegate": ["s/example74845"]
				break;
			case 'import':		// Imports specified entries from Namecoin names and merges with the current one. Modify the currently processed object. Latest modifications have precedence.
				# "import": [ ["d/example", "www"] ]
				break;
			case 'ns':
			case 'dns':
				unset($data->map);
				unset($data->ip);
				unset($data->ip6);
				unset($data->email);
				unset($data->translate);
				unset($data->alias);
				if(isset($data->dns)) {
					$data->ns = $data->dns;
					unset($data->dns);
				}
				break;
			case 'translate':	// delete all subdomains
				unset($data->map);
				break;
			case 'alias':		// remove all except alias & map
				foreach($data as $k => $v) {
					if (!in_array($k, array('alias', 'map'))) {
						unset($data->$k);
					}
				}
				break;
			case 'map':
				if(isset($data->map)) {
					foreach((array)$data->map as $subsub=>$subvalue) {
						$this->cleanBadRecords($data->map->$subsub);
					}
				}
				break;
			case 0:				// FIX to allow new syntax prior to old syntax
				if(isset($data->ns)) {
					if($data->map && $data->map->_empty_) { unset($data->map->_empty_->ns); }
				} elseif(isset($data->ip) && !isset($data->_empty_->ns)) {
					unset($data->map->_empty_);
				}
				break;
			default:
				break;
			}
		}
	}

	private function getFlatZones($domain, $sub, $value) {
		$mask['private_ip'] = '@^(10\.|169\.254\.|172\.(1[6-9][2[0-9]|3[0-1])|192\.168\.)@';
		$mask['private_ip6'] = '@^[fF][eE]80:@';
		$mask['email'] = '/^[^@]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$/';
		$mask['ip'] = '@^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$@';
		$mask['ip6'] = '@^((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(([0-9A-Fa-f]{1,4}:){0,5}:((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(::([0-9A-Fa-f]{1,4}:){0,5}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))$@';
		#$mask['ns'] = '@^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(([0-9A-Fa-f]{1,4}:){0,5}:((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(::([0-9A-Fa-f]{1,4}:){0,5}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:))$@';
		#$mask['ns'] = '@^('.substr($mask['ip'], 1, strlen($mask['ip'])-2).'|'.substr($mask['ip6'], 1, strlen($mask['ip6'])-2).')$@';
		$mask['ns'] = '@^([a-zA-Z0-9._-]+\.)*[a-zA-Z0-9._-]+\.?$@';
		$mask['alias'] = '@^([a-zA-Z0-9._-]+\.)*[a-zA-Z0-9._-]+\.?$@';
		#$mask['alias'] = '@^[a-zA-Z0-9._-]+\.[a-zA-Z0-9]+\.?$@';

		#$record = in_array($sub, array('', '_empty_')) ? $this->getSubDomainName($this->name) : $sub;
		$record = in_array($sub, array('', '_empty_')) ? '@' : $sub;
		$sub	= in_array($sub, array('', '_empty_')) ? '' : $sub;
		$fqdn	= $sub . ($sub ? '.' : '') . $domain;
		/*echo "<br /><b>FQDN : $fqdn</b>";
		echo "<br /><b>Domain : $domain</b>";
		echo "<br /><b>Record : $record</b>";
		echo "<br /><b>Sub : $sub</b>";
		$value2 = clone $value;
		unset($value2->map);
		echo "<br />Value : <pre>"; print_r($value2); echo "</pre>";
		echo "<br />";*/

		foreach((array)$value as $recordType=>$recordValue) {
			// FIX to allow old syntax
			$recordType = $recordType && $recordType != '_empty_' ? $recordType : 'ip';
			#echo "RECORD: ".$recordType."<br />"; var_dump($recordValue);


			switch((string)$recordType){
			case 'loc':			#TODO
				# "51 30 12.240 N 0 7 40.254 W 0m"
				# Geographic location information. 
			case 'service':		#TODO
				# [ ["imap", "tcp", 0, 0, 143, "mail.host.com."] ]
				# Used to identify hosts that support particular services as per DNS SRV records. (see #Service records) https://dot-bit.org/Domain_names#Service_records
			case 'delegate':	# TODO
				# ["s/example74845"]
				# Delegates control of this domain to the given Namecoin name, or a sub-domain entry defined within that name. All other entries are ignored.
				break;
			case 'import':		# TODO
				# [ ["d/example", "www"] ]
				# Imports specified entries from Namecoin names and merges with the current one.
				break;
			case 'email':
				if(preg_match($mask[$recordType], (string)$recordValue)) {
					$this->flatZones[$domain][$record][$recordType][0] = (string)$recordValue;
				}
				break;
			case 'ds':
				foreach((array)$recordValue as $i=>$n) {
					if(!is_array($n))
						continue;
					$tag  = $n[0];
					$algo = $n[1];
					$type = $n[2];
					$hash = strtoupper(bin2hex(base64_decode($n[3])));
					if(!filter_var($tag, FILTER_VALIDATE_INT) || $tag < 0 || $tag >= 65536)
						continue;
					if(!filter_var($algo, FILTER_VALIDATE_INT))
						continue;
					if(!filter_var($type, FILTER_VALIDATE_INT))
						continue;

					$rrdata = "$tag $algo $type $hash";
					$this->flatZones[$domain][$record][$recordType][$rrdata] = true;
				}
				if(isset($this->flatZones[$domain][$record][$recordType]))
					$this->flatZones[$domain][$record][$recordType] = (array)array_keys($this->flatZones[$domain][$record][$recordType]);
				break;
			case 'ns':
				foreach((array)$recordValue as $i=>$n) {
					$n = trim($n);
					if(!$n)
						continue;

					// exlude local ip & ip6
					if(filter_var($n, FILTER_VALIDATE_IP)) {
						#if(!filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
						if(preg_match($mask['private_ip'], $n) || preg_match($mask['private_ip6'], $n))
							continue;
						$ns = $this->getSubDomainName($this->name).".ns-glue";
						if(!preg_match($mask['ns'], $ns))
							continue;
						if (filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
							$this->flatZones[$domain][$record.".ns-glue"]['ip6'][] = $n;
						} elseif (filter_var($n, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
							$this->flatZones[$domain][$record.".ns-glue"]['ip'][] = $n;
						}
						$n = $ns;
					} else {
						$n = $n.(substr($n, -1) == '.' ? '' : '.');
					}

					if(!preg_match($mask['ns'], $n))
						continue;

					$this->flatZones[$domain][$record][$recordType][$n] = true;
				}
				if(isset($this->flatZones[$domain][$record][$recordType]))
					$this->flatZones[$domain][$record][$recordType] = (array)array_keys($this->flatZones[$domain][$record][$recordType]);
				break;
			case 'ip':
			case 'ip6':
				foreach((array)$recordValue as $i=>$n) {
					$n = trim($n);
					// resolve host
					if(!preg_match($mask[$recordType], $n)) {
						continue;
						/*if(!preg_match($mask['ns'], $n)) {
							continue;
						}
						$n = gethostbyname($n);*/
					}
					if(preg_match($mask[$recordType], $n)) {
						// only acccept ip/ip6 addresses
						if(!preg_match($mask[$recordType], $n))
							continue;

						// if ns : exlude local ip & ip6
						if($recordType == 'ns' && (preg_match($mask['private_ip'], $n) || preg_match($mask['private_ip6'], $n)))
							continue;
						if($n == '10.0.0.1')
							continue;

						$this->flatZones[$domain][$record][$recordType][] = $n;
					}
				}
				break;
			case 'alias':
				if (!preg_match($mask[$recordType], (string)$recordValue)) {
					continue;
				}
				$recordValue = trim($recordValue) ? trim($recordValue) : "@";
			case 'translate':
				$this->flatZones[$domain][$record][$recordType][] = $recordValue;
				break;
			case 'map':
				foreach((array)$value->map as $subsub=>$subvalue) {
					#if($subsub == '_empty_') continue;
					$subsub = $subsub . ($sub ? '.' : '') . $sub;
					$this->getFlatZones($domain, $subsub, $subvalue);
				}
				break;
			default:
				break;
			}
		}
	}

	private function convertFlatToBind() {
		$rec['email']		= ' IN  TXT    ';
		$rec['ip']			= ' IN  A      ';
		$rec['ip6']			= ' IN  AAAA   ';
		$rec['ns']			= ' IN  NS     ';
		$rec['ds']			= ' IN  DS     ';
		$rec['alias']		= ' IN  CNAME  ';
		$rec['translate']	= ' IN  DNAME  ';
		foreach($this->flatZones as $fZone=>$fSub) {
			foreach($fSub as $sub=>$records) {
				if(strpos($sub, "@") !== FALSE)
					$subdom = str_replace("@", $this->getSubDomainName($fZone), $sub);
				else
					$subdom = $sub.'.'.$this->getSubDomainName($fZone);
				#$subdom = ($sub!='@'?$sub.'.':'') . $this->getSubDomainName($fZone);
				#echo "$subdom : $sub - $fZone<br />";
				foreach($records as $record=>$values) {
					switch($record) {
					case 'email':
						#$this->bindZones[$fZone]['email'] = $values[0];
						#$this->bindForwards[$fZone][] = str_pad($subdom, 15, ' ').$rec[$record].'"Email: '.$values[0].'"';
						break;
					case 'alias':
					case 'translate':
					case 'ip':
					case 'ip6':
						#print_r($values);
						foreach($values as $value) {
							#$this->bindZones[$fZone][] = str_pad($sub, 8, ' ').' '.$rec[$record].$value;
							#$this->bindForwards[$fZone][] = str_pad($subdom, 15, ' ').$rec[$record].$value;
							$this->bindForwards[] = str_pad($subdom, 15, ' ').$rec[$record].$value;
						}
						break;
					case 'ds':
					case 'ns':
						foreach($values as $value) {
							#$this->bindForwards[($sub!='@'?$sub.'.':'').$fZone][] = $value;
							#$this->bindForwards[$fZone][] = str_pad($subdom, 15, ' ').$rec[$record].$value;
							$this->bindForwards[] = str_pad($subdom, 15, ' ').$rec[$record].$value;
						}
					}
				}
			}
		}
	}

	public function getBindZones() {
		$this->flatZones = array();
		$this->bindZones = array();
		#echo '<pre><b>'; print_r($this->name); echo '</b> : '; print_r($this->value['value']); echo '</pre>';
		#var_dump($this->json);
		if(is_object($this->json)) {
			// expired zone
			#if($this->value['is_expired'] == 1 || $this->value['expires_in'] < 1)
			if(isset($this->value['expired']) && $this->value['expired'] == 1)
			{
				return;
			}
			$this->j = $this->json;
			#echo "<br />Value BEFORE: <pre>"; print_r($this->j); echo "</pre>";
			$this->cleanBadRecords($this->j);
			#echo "<br />Value AFTER : <pre>"; print_r($this->j); echo "</pre>";
			$this->getFlatZones($this->getDomainName(), '', $this->j);
			#echo "<br />Flat zone : <pre>"; print_r($this->flatZones); echo '</pre>';
		}
		#echo '<pre>'; print_r($this->flatZones); echo '</pre>';

		$this->convertFlatToBind();
		if(!isset($this->bindForwards)) return;
		foreach((array)$this->bindForwards as $forward=>$val) {
			unset($this->bindZones[$forward]);
		}
		#echo '<pre>Zone : '; print_r($this->bindZones); echo '</pre>';
		#echo '<pre>Forward : '; print_r($this->bindForwards); echo '</pre>';

		#return $this->zones;
	}
}

?>
