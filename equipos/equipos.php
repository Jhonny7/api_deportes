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


/* Crear equipo*/
$app->put('/createEquipo', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $db->beginTransaction();
        $idEstatusActivo = 1;
        //Creación de level.
        $createEquipo = 'INSERT INTO equipo (`id_status`, `nombre`, `fecha_ult_modificacion`) VALUES (?, ?, now());';
        $nombre = $data['nombre'];
        $sthEquipo = $db->prepare($createEquipo);
        $sthEquipo->bindParam(1, $idEstatusActivo, PDO::PARAM_INT);
        $sthEquipo->bindParam(2, $nombre, PDO::PARAM_STR);
        $sthEquipo->execute();
        $idEquipo = $db->lastInsertId();

        //Commit exitoso de transacción
        $db->commit();

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $idEquipo;
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

/* Editar Equipo */
$app->post('/updateEquipo', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $db->beginTransaction();
        //Creación de level.UPDATE `futbol_americano_v1`.`equipo` SET `nombre` = 'sdfsds' WHERE (`id` = '1');
        $updateEquipo = 'UPDATE equipo SET nombre = ?, fecha_ult_modificacion = now(), id_status = ? WHERE id = ?';
        $nombre = $data['nombre'];
        $idEquipo = $data['idEquipo'];
        $idEstatus = $data['idEstatus'];
        $sthEquipo = $db->prepare($updateEquipo);
        $sthEquipo->bindParam(3, $idEquipo, PDO::PARAM_INT);
        $sthEquipo->bindParam(2, $idEstatus, PDO::PARAM_INT);
        $sthEquipo->bindParam(1, $nombre, PDO::PARAM_STR);
        $sthEquipo->execute();


        //Commit exitoso de transacción
        $db->commit();

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $idEquipo;
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

/* Eliminar Equipo lógicamente*/
$app->post('/deleteEquipo', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $db->beginTransaction();
        //Creación de level.UPDATE `futbol_americano_v1`.`equipo` SET `nombre` = 'sdfsds' WHERE (`id` = '1');
        $updateEquipo = 'UPDATE equipo SET fecha_ult_modificacion = now(), id_status = 2 WHERE id = ?';
        $idEquipo = $data['idEquipo'];
        $sthEquipo = $db->prepare($updateEquipo);
        $sthEquipo->bindParam(1, $idEquipo, PDO::PARAM_INT);
        $sthEquipo->execute();


        //Commit exitoso de transacción
        $db->commit();

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $idEquipo;
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

/* Agregar equipo a un jugador*/
$app->put('/addEquipoToPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        $db->beginTransaction();

        $body = $app->request->getBody();
        $data = json_decode($body, true);
        //Creación de level.UPDATE `futbol_americano_v1`.`equipo` SET `nombre` = 'sdfsds' WHERE (`id` = '1');
        $createLevel = 'INSERT INTO level (`id_status`, `level`) VALUES (1, ?)';
        $level = $data['level'];
        $sthLevel = $db->prepare($createLevel);
        $sthLevel->bindParam(1, $level, PDO::PARAM_STR);
        $sthLevel->execute();
        $idLevel = $db->lastInsertId();

        $createEstadistica = 'INSERT INTO estadistica (`id_level`) VALUES (?)';
        $sthEstadistica = $db->prepare($createEstadistica);
        $sthEstadistica->bindParam(1, $idLevel, PDO::PARAM_INT);
        $sthEstadistica->execute();
        $idEstadistica = $db->lastInsertId();

        $createJugadorEstadistica = 'INSERT INTO jugador_estadistica (`id_equipo`, `id_jugador`, `id_estadistica`) VALUES (?,?,?)';
        $sthJugadorEstadistica = $db->prepare($createJugadorEstadistica);
        $sthJugadorEstadistica->bindParam(1, $data['idEquipo'], PDO::PARAM_INT);
        $sthJugadorEstadistica->bindParam(2, $data['idJugador'], PDO::PARAM_INT);
        $sthJugadorEstadistica->bindParam(3, $idEstadistica, PDO::PARAM_INT);
        $sthJugadorEstadistica->execute();
        $idJugadorEstadistica = $db->lastInsertId();


        //Commit exitoso de transacción
        $db->commit();

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $idJugadorEstadistica;
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

/* Delete equipo a un jugador*/
$app->put('/removeEquipoFromPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        $db->beginTransaction();

        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $deleteJugadorEstadistica = 'DELETE FROM jugador_estadistica WHERE id_equipo = ?';

        $createLevel = 'INSERT INTO level (`id_status`, `level`) VALUES (1, ?)';
        $level = $data['level'];
        $sthLevel = $db->prepare($createLevel);
        $sthLevel->bindParam(1, $level, PDO::PARAM_STR);
        $sthLevel->execute();
        $idLevel = $db->lastInsertId();

        $createEstadistica = 'INSERT INTO estadistica (`id_level`) VALUES (?)';
        $sthEstadistica = $db->prepare($createEstadistica);
        $sthEstadistica->bindParam(1, $idLevel, PDO::PARAM_INT);
        $sthEstadistica->execute();
        $idEstadistica = $db->lastInsertId();

        $createJugadorEstadistica = 'INSERT INTO jugador_estadistica (`id_equipo`, `id_jugador`, `id_estadistica`) VALUES (?,?,?)';
        $sthJugadorEstadistica = $db->prepare($createJugadorEstadistica);
        $sthJugadorEstadistica->bindParam(1, $data['idEquipo'], PDO::PARAM_INT);
        $sthJugadorEstadistica->bindParam(2, $data['idJugador'], PDO::PARAM_INT);
        $sthJugadorEstadistica->bindParam(3, $idEstadistica, PDO::PARAM_INT);
        $sthJugadorEstadistica->execute();
        $idJugadorEstadistica = $db->lastInsertId();


        //Commit exitoso de transacción
        $db->commit();

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $idJugadorEstadistica;
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