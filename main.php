<?php
date_default_timezone_set('Asia/Tehran');
header('Content-Type: application/json');

$result = array(
        "last_update" => "",
        "last_timestamp" => 0,
        "ipv4" => array(),
        "ipv6" => array()
    );
    
$ips = [];

function resolve (){
    $data = json_decode(file_get_contents("providers.json") , true);

    foreach ($data as $key => $url_array){
    foreach ($url_array as $url){
        $dns_array = dns_get_record($url ,  DNS_A);
        foreach ($dns_array as $dns_data){
            $ips[] = [
                "ip" => $dns_data['ip'],
                "operator" => $key,
                "provider" => implode(".", array_slice(explode(".", $dns_data['host']), 1)),
                "created_at" => strtotime(date('Y-m-d H:i:s')),
            ];
        }
    }
}

$result = array(
        "last_update" => date('Y-m-d H:i:s'),
        "last_timestamp" => strtotime(date('Y-m-d H:i:s')),
        "ipv4" => $ips,
        "ipv6" => array()
    );
    
return $result;
}

function save(){
    $result = resolve();
    file_put_contents('list.json', json_encode($result, JSON_PRETTY_PRINT));
}

save();

?>
