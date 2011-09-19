<?php

function json_format($json) {
    $p = '';
    $nbtab = 0;
    $tab = "    ";
    $out = "";
    for($i=0; $i<strlen($json); $i++) {
        $c = $json[$i];
        $n = isset($json[$i+1]) ? $json[$i+1] : '';
        switch($c) {
            case '[':
            case '{':
                if($p == ':') { $nbtab++; $out .= "\n".str_repeat($tab, max(0, $nbtab)); }
                $out .= $c."\n".str_repeat($tab, max(0, ++$nbtab));
                break;
            case ']':
            case '}':
                $nbtab--;
                $out .= "\n".str_repeat($tab, max(0, $nbtab)).$c;
                #if($c == '}' && $n != ',') { $nbtab--; }
                if($c == ']') { $nbtab--; }
                break;
            case ',':
                if(in_array($p, array(']','}','"'))) {
                    #if($p == ']') { $nbtab--; }
                    $out .= $c."\n".str_repeat($tab, max(0, $nbtab));
                } else {
                    $out .= $c;
                }
                break;
            case ':':
                if($p == '"') { $out .= ' '; }
                $out .= $c;
                if($p == '"') { $out .= ' '; }
                break;
            default:
                $out .= $c;
                break;
        }
        $p = $c;
    }
    return $out;
}

function idna_to_unicode($name) {
	exec("LANG=en_US.UTF-8 /usr/bin/idn --allow-unassigned --usestd3asciirules --profile=Nameprep --idna-to-unicode '".$name."'", $out);
	if(count($out)) {
		return $out[0];
	}

	return false;
}

function unicode_to_idna($name) {
	exec("LANG=en_US.UTF-8 /usr/bin/idn --allow-unassigned --usestd3asciirules --profile=Nameprep --idna-to-ascii '".$name."'", $out);
	if(count($out)) {
		return strtolower($out[0]);
	}

	return false;
}
?>
