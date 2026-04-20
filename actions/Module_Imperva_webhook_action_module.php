<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';
include_once "Module_clean_webhook_action_module.php";
App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');


class Module_Imperva_webhook_action_module extends Module_clean_webhook_action_module
{
    public $id = 'imperva-api-webhook';
    public $name = 'Imperva API Webhook';
    public $version = '0.1';
    public $description = 'Es una extension del Webhook limpio. Permite la integracion con la API de Imperva para bloqueo de IPs entrantes.';
    public $icon_path = 'webhook.png';
    public $inputs = 1;
    public $outputs = 1;
    public $support_filters = true;
    public $params = [];

    private $timeout = false;
    private $Event;

    public function __construct()
    {
        parent::__construct();
        $this->params = [
            [
                'id' => 'url',
                'label' => __('URL'),
                'type' => 'input',
                'placeholder' => 'https://api.imperva.com/policies/v2/policies/',
		'default' => 'https://api.imperva.com/policies/v2/policies/',
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
                'id' => 'ioc_filter',
                'label' => 'IOC Filter',
                'type' => 'picker',
                'multiple' => true,
                'options' => ["ip-src", "ip-dst", "url", "domain", "hostname", "md5", "sha1", "sha256", "sha512"],
                'default' => ["ip-src"],
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
                    'post' => 'POST',
                    'put' => 'PUT',
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
            [
                'id' => 'headers',
                'label' => __('Headers'),
                'type' => 'textarea',
                'placeholder' => 'Accept: "*/*",
x-API-Id: ["ID"],
x-API-Key: ["KEY"]',
                'jinja_supported' => true,
            ],
        ];
    }

    private function checkPolicy($params, array &$errors = []){
	$url = $params["url"]["value"];
	$pid = intval($params["pid"]["value"]);
	$fullurl = $url . $pid . "?extended=true";

	$tmpHeaders = isset($params['headers']) ? explode(PHP_EOL, $params['headers']['value']) : [];
        $headers = [];
        $selfSignedAllowed = isset($params['self_signed']) ? $params['self_signed']['value'] == 'allow' : true;
        foreach ($tmpHeaders as $entry) {
            $entry = explode(':', $entry, 2);
            if (count($entry) == 2) {
                $headers[trim($entry[0])] = trim($entry[1]);
            }
        }
        $contentType = isset($params['content_type']) ? $params['content_type']['value'] : 'json';

        $res = $this->doRequest($fullurl, $contentType, NULL, $headers, "get", ['self_signed' => $selfSignedAllowed]);
        if ($res->isOk()) {
            return $res->json();
        }
        $errors[] = __('Something went wrong with the checkPolicy request or the remote side is having issues. Body returned: %s', $res->body);
	return false;
    }

    private function getPsidFromPolicy($pol){
	foreach ($pol["value"]["policySettings"] as $setting){
	    if($setting["policySettingType"] == "IP"){
	        return $setting["id"];	    
	    }
	}
	return false;
    }

    private function getIPsFromPolicy($pol){
	$ips = [];
	foreach ($pol["value"]["policySettings"] as $setting){
	    if($setting["policySettingType"] == "IP"){
	        return $setting["data"]["ips"];	    
	    }
	}
	return $ips;
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
	file_put_contents("/tmp/dump_data.log",print_r("Iniciando el EXEC.", true));
	file_put_contents("/tmp/dump_data.log",print_r($params, true), FILE_APPEND);
	file_put_contents("/tmp/dump_data.log",print_r($rData, true), FILE_APPEND);
        if (empty($params['url']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }
        if (empty($params['pid']['value'])) {
            $errors[] = __('Policy ID not provided.');
            return false;
	}

	$pid = $params['pid']['value'];

	if (intval($pid) == 0) {
	    $errors[] = __('Policy ID tiene que ser un número (no puede ser 0).');
	    return false;
	} else
	{
	    $res = $this->checkPolicy($params, $errors);
	    if(!$res){
		$errors[] = __('La politica con el ID: '.$pid.' no existe.');
		return false;
	    }
	    $psid = $this->getPsidFromPolicy($res);
	    $ips = $this->getIPsFromPolicy($res);
	    if(!$psid){
		$errors[] = __('La politica con el ID: '.$pid.' no tiene PSID?.');
		return false;
	    }
	}

	$filter = $params["ioc_filter"]["value"];

        $payload = $rData;
	$payload = $this->getOnlyDataFromEventList($payload, $filter);
	if(count($payload) == 0){
	    return false;
	}
	file_put_contents("/tmp/dump_data.log",print_r("Ahora si entramos, porque tenemos payload.", true), FILE_APPEND);
	file_put_contents("/tmp/dump_data.log",print_r($payload, true), FILE_APPEND);

	$diff = array_values(array_diff($payload, $ips));
	if(count($diff) == 0){
	    return false;
	}
	$full_payload = [
	    "policySettings" => [ [
                "id" => $psid,
	        "policyId" => $pid,		    
	        "policySettingType" => "IP",		    
	        "data" => [
	            "headerValue" => NULL,
	            "geo" => NULL,
	            "urls" => NULL,
	            "ips" => $diff
		],
	    ],
	    ]
	];

	file_put_contents("/tmp/dump_data.log",print_r($full_payload, true), FILE_APPEND);
        $tmpHeaders = isset($params['headers']) ? explode(PHP_EOL, $params['headers']['value']) : [];
        $headers = [];
        $selfSignedAllowed = isset($params['self_signed']) ? $params['self_signed']['value'] == 'allow' : true;
        foreach ($tmpHeaders as $entry) {
            $entry = explode(':', $entry, 2);
            if (count($entry) == 2) {
                $headers[trim($entry[0])] = trim($entry[1]);
            }
        }
        $requestMethod = isset($params['request_method']) ? $params['request_method']['value'] : 'post';
        $contentType = isset($params['content_type']) ? $params['content_type']['value'] : 'json';
        try {
            $response = $this->doRequest($params['url']['value'].$pid, $contentType, $full_payload, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
            if ($response->isOk()) {
                return true; 
            }
            if ($response->code === 403 || $response->code === 401) {
                $errors[] = __('Authentication failed.');
                return false;
            }
            $errors[] = __('Something went wrong with the request for Imperva or the remote side is having issues. Body returned: %s', $response->body);
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
