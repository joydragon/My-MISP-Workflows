<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_clean_webhook_action_module extends WorkflowBaseActionModule
{
    public $id = 'clean-webhook';
    public $name = 'Clean Webhook';
    public $version = '0.1';
    public $description = 'Permite generar llamadas a URL solo con los datos de los valores de los atributos (sin tanta challa). Es una extension del Webhook normal';
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
                'placeholder' => 'https://example.com/test',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'ioc_filter',
                'label' => 'IOC Filter',
                'type' => 'picker',
                'multiple' => true,
                'options' => ["ip-src", "ip-dst", "url", "domain", "md5", "sha1", "sha256", "sha512"],
                'default' => [],
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
                    'get' => 'GET',
                    'put' => 'PUT',
                    'delete' => 'DELETE',
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
                'id' => 'payload',
                'label' => __('Payload (leave empty for roaming data)'),
                'type' => 'textarea',
                'default' => '',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
            [
                'id' => 'headers',
                'label' => __('Headers'),
                'type' => 'textarea',
                'placeholder' => 'Authorization: foobar',
                'jinja_supported' => true,
            ],
        ];
    }

    private function mergeData(array $arr1, array $arr2, bool $addType){
        if (!$addType){
            return array_merge($arr1, $arr2);
        }

        foreach ($arr2 as $type => $values) {
            if(!array_key_exists($type, $arr1)){
                $arr1[$type] = [];
            }
            foreach($values as $v){
                $arr1[$type][] = $v;
            }
        }

        return $arr1;
    }

    protected function getDataFromAttributeList($attrArray, $filter, $addType = false){
	$res = [];
	foreach($attrArray as $attr){
	    if($attr["to_ids"] == True){
		if(is_array($filter) && (count($filter) == 0 || in_array($attr["type"], $filter) ) ){
		    if($addType){
		        if(!array_key_exists($attr["type"], $res)){
			    $res[$attr["type"]] = array();
		        }
			array_push($res[$attr["type"]], $attr["value"]);
		    }
		    else{
			array_push($res, $attr["value"]);
		    }
		}
	    }
	}
	return $res;
    }

    protected function getOnlyDataFromEventList($eventData, $filter, $addType = false){
	$res = [];
	if(is_array($eventData)){
	    foreach($eventData as $ev){
	        if(is_array($ev) && array_key_exists("Object", $ev)){
	    	    foreach($ev['Object']as $obj){
			$res = $this->mergeData($res, $this->getDataFromAttributeList($obj["Attribute"], $filter, $addType), $addType);
	    	    }
	        }
	        if(is_array($ev) && array_key_exists("Attribute", $ev)){
		    $res = $this->mergeData($res, $this->getDataFromAttributeList($obj["Attribute"], $filter, $addType), $addType);
	        }
	    }
	    return $res;
	}
    }

    public function diagnostic(): array
    {
        $errors = array_merge(parent::diagnostic(), []);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors = $this->addNotification(
                $errors,
                'error',
                __('`rest_client_enable_arbitrary_urls` is turned off.'),
                __('The module will not send any request as long as `Security.rest_client_enable_arbitrary_urls` is turned off.'),
                [
                    __('This is a security measure to ensure a site-admin do not send arbitrary request to internal services')
                ],
                true,
                true
            );
        }
        return $errors;
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        if (empty(Configure::read('Security.rest_client_enable_arbitrary_urls'))) {
            $errors[] = __('`Security.rest_client_enable_arbitrary_urls` is turned off');
            return false;
        }
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['url']['value'])) {
            $errors[] = __('URL not provided.');
            return false;
        }

	$filter = $params["ioc_filter"]["value"];

        $payload = '';
        if (isset($params['payload']) && strlen($params['payload']['value']) > 0) {
            $payload = $params['payload']['value'];
        } else {
            $payload = $rData;
	    $payload = $this->getOnlyDataFromEventList($payload, $filter);
        }
        if (!isset($params['content_type']) || $params['content_type']['value'] == 'json') {
            try {
                if (!is_string($payload)) {
                    $payload = json_encode($payload, JSON_PRETTY_PRINT, 512);
                    //$payload = json_decode($payload, true, 512, JSON_THROW_ON_ERROR);
                }
            } catch (Exception $e) {
                // Do nothing. simply send the payload as is
            }
        }
#	file_put_contents("/tmp/dump_data.log", "HOLA!!\n");
#	file_put_contents("/tmp/dump_data.log", print_r($filter, true), FILE_APPEND);
#	file_put_contents("/tmp/dump_data.log", print_r($payload, true), FILE_APPEND);
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
            $response = $this->doRequest($params['url']['value'], $contentType, $payload, $headers, $requestMethod, ['self_signed' => $selfSignedAllowed]);
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

    protected function doRequest($url, $contentType, $data, $headers = [], $requestMethod='post', $serverConfig = null)
    {
        $this->Event = ClassRegistry::init('Event'); // We just need a model to use AppModel functions
        $version = implode('.', $this->Event->checkMISPVersion());
        $commit = $this->Event->checkMIPSCommit();

        $request = [
            'header' => array_merge([
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            ], $headers)
        ];
        $syncTool = new SyncTool();
        $serverConfig = !empty($serverConfig['Server']) ? $serverConfig : ['Server' => $serverConfig];
        $HttpSocket = $syncTool->setupHttpSocket($serverConfig, $this->timeout);
        $encodedData = $data;
        if ($contentType == 'form') {
            $request['header']['Content-Type'] = 'application/x-www-form-urlencoded';
        } else {
            $encodedData = JsonTool::encode($data);
        }
        switch ($requestMethod) {
            case 'post':
                $response = $HttpSocket->post($url, $encodedData, $request);
                break;
            case 'get':
                $response = $HttpSocket->get($url, false, $request);
                break;
            case 'put':
                $response = $HttpSocket->put($url, $encodedData, $request);
                break;
            case 'delete':
                $response = $HttpSocket->delete($url, $encodedData, $request);
                break;
        }
        return $response;
    }
}
