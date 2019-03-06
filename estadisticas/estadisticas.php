<?php
header("Access-Control-Allow-Origin: *");
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: PUT, GET, POST, DELETE, OPTIONS');
header("Access-Control-Allow-Headers: X-Requested-With");
header('Content-Type: text/html; charset=utf-8');
header('P3P: CP="IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"'); 

require_once '../include/DbHandler.php'; 

require '../libs/Slim/Slim.php'; 

\Slim\Slim::registerAutoloader(); 
$app = new \Slim\Slim(); 


/* Actualizar estadísticas de equipo por usuario*/
$app->post('/updateTeamStatisticsFromPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        $db->beginTransaction();

        $body = $app->request->getBody();
        $data = json_decode($body, true);
        //Creación de level.UPDATE `futbol_americano_v1`.`equipo` SET `nombre` = 'sdfsds' WHERE (`id` = '1');
        $updateEstadistica = 'UPDATE estadistica SET 
                        touch_pass = ?, annotation_by_race = ?, annotation_by_pass = ?, 
                        interceptions = ?, sachs = ?, conversions = ? WHERE id = ?';
        
        $touch_pass = $data['touch_pass'];
        $annotation_by_race = $data['annotation_by_race'];
        $annotation_by_pass = $data['annotation_by_pass'];
        $interceptions = $data['interceptions'];
        $sachs = $data['sachs'];
        $conversions = $data['conversions'];
        $id = $data['id'];

        $sthEstadistica = $db->prepare($updateEstadistica);
        $sthEstadistica->bindParam(1, $touch_pass, PDO::PARAM_INT);
        $sthEstadistica->bindParam(2, $annotation_by_race, PDO::PARAM_INT);
        $sthEstadistica->bindParam(3, $annotation_by_pass, PDO::PARAM_INT);
        $sthEstadistica->bindParam(4, $interceptions, PDO::PARAM_INT);
        $sthEstadistica->bindParam(5, $sachs, PDO::PARAM_INT);
        $sthEstadistica->bindParam(6, $conversions, PDO::PARAM_INT);
        $sthEstadistica->bindParam(7, $id, PDO::PARAM_INT);
        $sthEstadistica->execute();


        //Commit exitoso de transacción
        $db->commit();

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = [];
        $response["timeRequest"] = date("Y-m-d H:i:s");
        echoResponse(200, $response);
    }catch(Exception $e){
        $db->rollBack();
        $response["status"] = "I";
        $response["description"] = $e->getMessage();
        $response["idTransaction"] = time();
        $response["parameters"] = $e;
        $response["timeRequest"] = date("Y-m-d H:i:s");
        echoResponse(400, $response);
    }
});

/* Obtener estadisticas generales por jugador*/
$app->get('/getGeneralStatisticsByPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        $idJugador = $app->request()->params('idJugador');
        //Creación de level.
        $createEquipo = 'SELECT 
                        sum(e.touch_pass) as touch_pass,
                        sum(e.annotation_by_race) as annotation_by_race,
                        sum(e.annotation_by_pass) as annotation_by_pass,
                        sum(e.interceptions) as interceptions,
                        sum(e.sachs) as sachs,
                        sum(e.conversions) as conversions
                        FROM jugador_estadistica je
                        INNER JOIN estadistica e ON (je.id_estadistica = e.id)
                        INNER JOIN equipo eq ON (eq.id = je.id_equipo)
                        WHERE je.id_jugador = ? AND eq.id_status = 1';
        $sthEquipo = $db->prepare($createEquipo);
        $sthEquipo->bindParam(1, $idJugador, PDO::PARAM_INT);
        $sthEquipo->execute();
        $rows = $sthEquipo->fetchAll(PDO::FETCH_ASSOC);
        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $rows;
        $response["timeRequest"] = date("Y-m-d H:i:s");
        echoResponse(200, $response);
    }catch(Exception $e){
        $response["status"] = "I";
        $response["description"] = $e->getMessage();
        $response["idTransaction"] = time();
        $response["parameters"] = $e;
        $response["timeRequest"] = date("Y-m-d H:i:s");
        echoResponse(400, $response);
    }
});

/* corremos la aplicación */
$app->run();

/*********************** USEFULL FUNCTIONS **************************************/

/**
 * Verificando los parametros requeridos en el metodo o endpoint
 */
function verifyRequiredParams($required_fields) {
    $error = false;
    $error_fields = "";
    $request_params = array();
    $request_params = $_REQUEST;
    // Handling PUT request params
    if ($_SERVER['REQUEST_METHOD'] == 'PUT') {
        $app = \Slim\Slim::getInstance();
        parse_str($app->request()->getBody(), $request_params);
    }
    foreach ($required_fields as $field) {
        if (!isset($request_params[$field]) || strlen(trim($request_params[$field])) <= 0) {
            $error = true;
            $error_fields .= $field . ', ';
        }
    }
 
    if ($error) {
        // Required field(s) are missing or empty
        // echo error json and stop the app
        $response = array();
        $app = \Slim\Slim::getInstance();


        $response["status"] = "I";
        $response["description"] = 'Campo(s) Requerido(s) ' . substr($error_fields, 0, -2) . '';
        $response["idTransaction"] = time();
        $response["parameters"] = [];
        $response["timeRequest"] = date("Y-m-d H:i:s");

        echoResponse(400, $response);
        
        $app->stop();
    }
}
 
/**
 * Validando parametro email si necesario; un Extra ;)
 */
function validateEmail($email) {
    $app = \Slim\Slim::getInstance();
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $response["error"] = true;
        $response["message"] = 'Email address is not valid';
        echoResponse(400, $response);
        
        $app->stop();
    }
}
 
/**
 * Mostrando la respuesta en formato json al cliente o navegador
 * @param String $status_code Http response code
 * @param Int $response Json response
 */
function echoResponse($status_code, $response) {
    $app = \Slim\Slim::getInstance();
    // Http response code
    $app->status($status_code);
 
    // setting response content type to json
    $app->contentType('application/json');
 
    echo json_encode($response);
}

/**
 * Agregando un leyer intermedio e autenticación para uno o todos los metodos, usar segun necesidad
 * Revisa si la consulta contiene un Header "Authorization" para validar
 */
function authenticate(\Slim\Route $route) {
    // Getting request headers
    $headers = apache_request_headers();
    $response = array();
    $app = \Slim\Slim::getInstance();
 
    // Verifying Authorization Header
    if (isset($headers['Authorization'])) {
        //$db = new DbHandler(); //utilizar para manejar autenticacion contra base de datos
 
        // get the api key
        $token = $headers['Authorization'];
        
        // validating api key
        if (!($token == API_KEY)) { //API_KEY declarada en Config.php
            
            // api key is not present in users table
            $response["error"] = true;
            $response["message"] = "Acceso denegado. Token inválido";
            echoResponse(401, $response);
            
            $app->stop(); //Detenemos la ejecución del programa al no validar
            
        } else {
            //procede utilizar el recurso o metodo del llamado
        }
    } else {
        // api key is missing in header
        $response["error"] = true;
        $response["message"] = "Falta token de autorización";
        echoResponse(400, $response);
        
        $app->stop();
    }
}

/*
 *Función para encriptar contraseñas
 */
function dec_enc($action, $string) {
    $output = false;
 
    $encrypt_method = "AES-256-CBC";
    $secret_key = 'This is my secret key';
    $secret_iv = 'This is my secret iv';
 
    // hash
    $key = hash('sha256', $secret_key);
    
    // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
    $iv = substr(hash('sha256', $secret_iv), 0, 16);
 
    if( $action == 'encrypt' ) {
        $output = openssl_encrypt($string, $encrypt_method, $key, 0, $iv);
        $output = base64_encode($output);
    }
    else if( $action == 'decrypt' ){
        $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, 0, $iv);
    }
 
    return $output;
}
?>