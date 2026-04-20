<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';
include_once "Module_clean_webhook_action_module.php";
App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_Crowdstrike_webhook_action_module extends Module_clean_webhook_action_module
{
    public $id = 'crowdstrike-api-webhook';
    public $name = 'Crowdstrike API Webhook';
    public $version = '0.1';
    public $description = 'Es una extension del Webhook limpio. Permite la integracion con Falcon de Crowdstrike para bloqueo de dominios';
    public $icon_path = 'webhook.png';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $params = [];

    private $timeout = false;
    private $Event;
    private $token_file = "/tmp/.crowdstrike_token.json";

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'base_domain',
                'label' => __('BASE Domain'),
                'type' => 'input',
		'placeholder' => 'api.us-2.crowdstrike.com',
		'default' => 'api.us-2.crowdstrike.com',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'client_id',
                'label' => __('Client ID'),
                'type' => 'input',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
            [
                'id' => 'client_secret',
                'label' => __('Client Secret'),
                'type' => 'input',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'expiration',
                'label' => __('Expiration Time (in days)'),
                'type' => 'input',
		'placeholder' => '90',
		'default' => 90,
                'jinja_supported' => true,
            ],
	    [
                'id' => 'ioc_filter',
                'label' => 'IOC Filter',
                'type' => 'picker',
                'multiple' => true,
                'options' => ["ip-src", "ip-dst", "url", "domain", "hostname", "md5", "sha1", "sha256", "sha512"],
                'default' => ["domain", "md5", "sha256"],
                'placeholder' => __('Pick the IOC Filter (optional)')
            ],
            [
                'id' => 'content_type',
                'label' => __('Content type'),
                'type' => 'select',
                'default' => 'json',
                'options' => [
                    'json' => 'application/json',
                    'form' => 'application/x-www-form-urlencoded',
                ],
            ],
            [
                'id' => 'request_method',
                'label' => __('HTTP Request Method'),
                'type' => 'select',
                'default' => 'post',
                'options' => [
                    'post' => 'POST'
                ],
            ],
            [
                'id' => 'self_signed',
                'label' => __('Self-signed certificates'),
                'type' => 'select',
                'default' => 'deny',
                'options' => [
                    'deny' => 'Deny self-signed certificates',
                    'allow' => 'Allow self-signed certificates',
                ],
            ],
        ];
    }

    private function getOnlineToken($params){
	$url = "https://".$params["base_domain"]["value"]."/oauth2/token";
	$client_id = $params["client_id"]["value"];
	$client_secret = $params["client_secret"]["value"];
	$headers["Authorization"] = "Basic ".base64_encode($client_id.":".$client_secret);
	$requestMethod = "post";
        $selfSignedAllowed = isset($params['self_signed']) ? $params['self_signed']['value'] == 'allow' : true;
        $response = $this->doRequest($url, "form", NULL, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
	if($response->isOk()){
	    $time = time();
	    $json = $response->json();
	    $json["expires_at"] = intval($time + $json["expires_in"]);

	    file_put_contents($this->token_file,json_encode($json));
	    return $json;
	}
	return false;
    }

    private function checkToken($params){
        if(file_exists($this->token_file)){
	    $token = json_decode(file_get_contents($this->token_file), true);
	    if( $token != NULL && 
		    array_key_exists("access_token", $token) && 
		    array_key_exists("expires_at", $token) ){
		$time = time();
		if ( $token["expires_at"] > $time ){
		    return $token;
		}
	    }
	}
	return $this->getOnlineToken($params);
    }

    private function limpiarPayload($full_payload, $response){
	$body = $response->json();
	foreach($body["resources"] as $r){
	    for($i = 0; $i < count($full_payload["indicators"]); $i++){
		if($full_payload["indicators"][$i]["type"] == $r["type"] && $full_payload["indicators"][$i]["value"] == $r["value"]){
		    $full_payload["indicators"] = array_splice($full_payload["indicators"], $i, 1);
		    $i--;
		    break;
		}
	    }
	}
	if(count($full_payload["indicators"]) == 0){
	    return false;
	}
	return $full_payload;
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        #parent::exec($node, $roamingData, $errors);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors[] = __('`Security.rest_client_enable_arbitrary_urls` is turned off');
            return false;
        }
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
	file_put_contents("/tmp/dump_data_CS.log",print_r("Iniciando el EXEC.", true));
	file_put_contents("/tmp/dump_data_CS.log",print_r($params, true), FILE_APPEND);
	file_put_contents("/tmp/dump_data_CS.log",print_r($rData, true), FILE_APPEND);
        if (empty($params['base_domain']['value'])) {
            $errors[] = __('Base Domain not provided.');
            return false;
        }
        if (empty($params['client_id']['value'])) {
            $errors[] = __('Client ID not provided.');
            return false;
	}
        if (empty($params['client_secret']['value'])) {
            $errors[] = __('Client Secret not provided.');
            return false;
	}

	$token = $this->checkToken($params);
	file_put_contents("/tmp/dump_data_CS.log",print_r($token, true), FILE_APPEND);
	
	if(!$token){
	    return false;
	}

	$filter = $params["ioc_filter"]["value"];

        $payload = $rData;
	$iocs = $this->getOnlyDataFromEventList($payload, $filter, true);

	if(count($iocs) == 0){
	    return false;
	}
	
	file_put_contents("/tmp/dump_data_CS.log",print_r($iocs, true), FILE_APPEND);
	$full_payload = [
		"comment" => "IOC extraido de evento " . $payload["Event"]["id"] . " de MISP.",
		"ignore_warnings" => true,
		"indicators" => []
	];
	foreach($iocs as $ioc_type => $ioc){
	    foreach($ioc as $i){		
		$aux = [
		    "type" => $ioc_type,
		    "value" => $i,
		    "description" => "IOC extraido de evento " . $payload["Event"]["id"] . " de MISP.",
		    "severity" => "medium",
		    "action" => ($ioc_type == "domain") ? "detect" :"prevent",
		    "platforms" => ["windows","linux","mac"],
		    "applied_globally" => true
		];
		if(isset($params['expiration']) && is_int($params['expiration']['value'])){
		    $dexpiration = date('c', strtotime("+" . $params['expiration']['value'] . " days"));
		    $aux["expiration"] = $dexpiration;
		}
		$full_payload["indicators"][] = $aux; 
	    }
	}

	file_put_contents("/tmp/dump_data_CS.log",print_r($full_payload, true), FILE_APPEND);

	$headers = [];
        $headers["Authorization"] = "Bearer " . $token["access_token"];
        $selfSignedAllowed = isset($params['self_signed']) ? $params['self_signed']['value'] == 'allow' : true;
        $requestMethod = isset($params['request_method']) ? $params['request_method']['value'] : 'post';
        $contentType = isset($params['content_type']) ? $params['content_type']['value'] : 'json';
        try {
	    $full_url = "https://".$params["base_domain"]["value"]."/iocs/entities/indicators/v1";
            $response = $this->doRequest($full_url, $contentType, $full_payload, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
            if ($response->isOk()) {
                return true;
            }
	    if ($response->code === 400) {
		    file_put_contents("/tmp/dump_data_CS.log","Tenemos algunos errores que vamos a intentar resolver.\n", FILE_APPEND);
		    file_put_contents("/tmp/dump_data_CS.log",print_r($response, true), FILE_APPEND);
		    $res = $this->limpiarPayload($full_payload, $response);

		    file_put_contents("/tmp/dump_data_CS.log","Finalmente quedamos con.\n", FILE_APPEND);
		    file_put_contents("/tmp/dump_data_CS.log",print_r($res, true), FILE_APPEND);
		    if(!$res){
		    	return false;
		    }
		    $response = $this->doRequest($full_url, $contentType, $full_payload, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
		    file_put_contents("/tmp/dump_data_CS.log",print_r($res, true), FILE_APPEND);
	    }
            if ($response->code === 403 || $response->code === 401) {
                $errors[] = __('Authentication failed.');
                return false;
            }
            $errors[] = __('Something went wrong with the request or the remote side is having issues. Body returned: %s', $response->body);
            return false;
        } catch (SocketException $e) {
            $errors[] = __('Something went wrong while sending the request. Error returned: %s', $e->getMessage());
            return false;
        } catch (Exception $e) {
            $errors[] = __('Something went wrong. Error returned: %s', $e->getMessage());
            return false;
        }
        $errors[] = __('Something went wrong with the request or the remote side is having issues.');
        return false;
    }
}
