<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';
include_once "Module_clean_webhook_action_module.php";
App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_SecureAccess_webhook_action_module extends Module_clean_webhook_action_module
{
    public $id = 'secure-access-api-webhook';
    public $name = 'Secure Access API Webhook';
    public $version = '0.1';
    public $description = 'Es una extension del Webhook limpio. Permite la integracion con Secure Access de CISCO para bloqueo de dominios';
    public $icon_path = 'webhook.png';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $params = [];

    private $timeout = false;
    private $Event;
    private $token_file = "/tmp/.cisco_token.json";

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'url',
                'label' => __('URL'),
                'type' => 'input',
                'placeholder' => 'https://api.sse.cisco.com/policies/v2/destinationlists/',
		'default' => 'https://api.sse.cisco.com/policies/v2/destinationlists/',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'pid',
                'label' => __('Policy ID'),
                'type' => 'input',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'api_key',
                'label' => __('API Key'),
                'type' => 'input',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
            [
                'id' => 'api_secret',
                'label' => __('API Secret'),
                'type' => 'input',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'ioc_filter',
                'label' => 'IOC Filter',
                'type' => 'picker',
                'multiple' => true,
                'options' => ["ip-src", "ip-dst", "url", "domain", "hostname", "md5", "sha1", "sha256", "sha512"],
                'default' => ["domain"],
                'placeholder' => __('Pick the IOC Filter (optional)')
            ],
        ];
    }

    private function getOnlineToken($params){
	$url = "https://api.sse.cisco.com/auth/v2/token";
	$api_key = $params["api_key"]["value"];
	$api_secret = $params["api_secret"]["value"];
	$headers["Authorization"] = "Basic ".base64_encode($api_key.":".$api_secret);
	$requestMethod = "get";
        $selfSignedAllowed = isset($params['self_signed']) ? $params['self_signed']['value'] == 'allow' : true;
        $response = $this->doRequest($url, "json", NULL, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
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

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        #parent::exec($node, $roamingData, $errors);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors[] = __('`Security.rest_client_enable_arbitrary_urls` is turned off');
            return false;
        }
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
//	file_put_contents("/tmp/dump_data_SA.log",print_r("Iniciando el EXEC.", true));
//	file_put_contents("/tmp/dump_data_SA.log",print_r($params, true), FILE_APPEND);
//	file_put_contents("/tmp/dump_data_SA.log",print_r($rData, true), FILE_APPEND);
        if (empty($params['url']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }
        if (empty($params['pid']['value'])) {
            $errors[] = __('Policy ID not provided.');
            return false;
	}
        if (empty($params['api_key']['value'])) {
            $errors[] = __('API Key not provided.');
            return false;
	}
        if (empty($params['api_secret']['value'])) {
            $errors[] = __('API Secret not provided.');
            return false;
	}

	$pid = $params['pid']['value'];
	if (intval($pid) == 0) {
	    $errors[] = __('Policy ID tiene que ser un número (no puede ser 0).');
	    return false;
	}

	$token = $this->checkToken($params);
//	file_put_contents("/tmp/dump_data_SA.log",print_r($token, true), FILE_APPEND);

	$filter = $params["ioc_filter"]["value"];

        $payload = $rData;
	$iocs = $this->getOnlyDataFromEventList($payload, $filter);

	if(count($iocs) == 0){
	    return false;
	}
	
//	file_put_contents("/tmp/dump_data_SA.log",print_r($iocs, true), FILE_APPEND);
	$full_payload = [];
	foreach($iocs as $i){
	    $full_payload[] = [
		"destination" => $i,
		"comment" => "IOC extraido de evento " . $payload["Event"]["id"] . " de MISP."
	    ];
	}

//	file_put_contents("/tmp/dump_data_SA.log",print_r($full_payload, true), FILE_APPEND);
	
	$headers = [];
        $headers["Authorization"] = "Bearer " . $token["access_token"];
	
	$selfSignedAllowed = false;
	$requestMethod = "post";
	$contentType = "json";

        try {
	    $full_url = $params['url']['value'].$pid."/destinations";
            $response = $this->doRequest($full_url, $contentType, $full_payload, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
            if ($response->isOk()) {
                return true;
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
