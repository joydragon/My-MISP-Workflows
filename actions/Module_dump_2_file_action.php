<?php
include_once APP . 'Model/WorkflowModules/WorkflowBaseModule.php';

App::uses('SyncTool', 'Tools');
App::uses('JsonTool', 'Tools');

class Module_dump_2_file_action extends WorkflowBaseActionModule
{
    public $id = 'dump-2-file';
    public $name = 'Dump IOC to File';
    public $version = '0.1';
    public $description = '';
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
                'id' => 'filename',
                'label' => __('File Name'),
                'type' => 'input',
                'placeholder' => '',
                'jinja_supported' => true,
            ],
	    [
                'id' => 'base_folder',
                'label' => 'Base Folder',
                'type' => 'input',
		'placeholder' => '/var/www/MISP/app/webroot/edl/',
		'default' => '/var/www/MISP/app/webroot/edl/',
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
                'id' => 'append_data',
                'label' => __('Append Data'),
                'type' => 'checkbox',
                'default' => false,
            ],
        ];
    }

    private function mergeData(array $arr1, array $arr2, bool $addType = false){
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
		    $res = $this->mergeData($res, $this->getDataFromAttributeList($ev["Attribute"], $filter, $addType), $addType);
	        }
	    }
	    return $res;
	}
    }

    public function exec(array $node, WorkflowRoamingData $roamingData, array &$errors = []): bool
    {
        parent::exec($node, $roamingData, $errors);
        $rData = $roamingData->getData();
        $params = $this->getParamsWithValues($node, $rData);
        if (empty($params['filename']['value'])) {
            $errors[] = __('File Name not provided.');
            return false;
        }

	if (empty($params['base_folder']['value'])) {
            $errors[] = __('Base Folder not provided.');
            return false;
	}
	else{
	    if(!is_dir($params['base_folder']['value'])){
		mkdir($params['base_folder']['value'], 0755, true);
	    }
	}

	$append = $params["append_data"]["value"];
	$file_path = $params['base_folder']['value'] . $params['filename']['value'];
	$filter = $params['ioc_filter']['value'];

	file_put_contents("/tmp/dump_data.log",print_r("Ahora si entramos, porque tenemos payload.\n\n", true));
	file_put_contents("/tmp/dump_data.log",print_r($params, true), FILE_APPEND);

        $payload = '';
        if (isset($params['payload']) && strlen($params['payload']['value']) > 0) {
            $payload = $params['payload']['value'];
	} else {
	    $payload = [];
	    $temp = $this->getOnlyDataFromEventList($rData, $filter);
	    file_put_contents("/tmp/dump_data.log",print_r($temp, true), FILE_APPEND);
	    $payload = $this->mergeData($payload, $temp);
        }
	if($append){
	# Si hay que agregar datos y deduplicar
	    file_put_contents("/tmp/dump_data.log","Deduplicando! \n", FILE_APPEND);
            $base_payload = [];
	    $handle = fopen($file_path, "r");
	    while (($line = fgets($handle)) !== false) {
	        if($line != ""){
	            $base_payload[] = trim($line);
		}
	    }
	    fclose($handle);
	    $result = [...$base_payload, ...$payload];
	    $payload = array_unique($result);
	    sort($payload);
	    file_put_contents("/tmp/dump_data.log",print_r($payload, true), FILE_APPEND);
	}
	
	# Se elimina lo anterior para agregar lo deduplicado (o no).
	if(is_file($file_path)){
	    unlink($file_path);
	}
	foreach($payload as $ioc){
	    file_put_contents($file_path, print_r($ioc, true) . "\n", FILE_APPEND);
	}
	return false;
    }
}
