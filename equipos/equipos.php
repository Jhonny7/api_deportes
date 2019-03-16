<?php
header("Access-Control-Allow-Origin: *");
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Methods: PUT, GET, POST, DELETE, OPTIONS');
header("Access-Control-Allow-Headers: X-Requested-With");
header('Content-Type: text/html; charset=utf-8');
header('P3P: CP="IDC DSP COR CURa ADMa OUR IND PHY ONL COM STA"'); 

require_once '../include/DbHandler.php'; 
require_once '../services/fcm_service.php'; 

require '../libs/Slim/Slim.php'; 

\Slim\Slim::registerAutoloader(); 
$app = new \Slim\Slim(); 

/* Obtener equipor por jugador*/
$app->get('/getTeamsByPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        //Creación de level.
        $createEquipo = 'SELECT 
                        u.id_jugador,
                        u.id as id_usuario,
                        je.id_equipo,
                        je.id_estadistica,
                        eq.nombre as nombre_equipo,
                        e.touch_pass,
                        e.annotation_by_pass,
                        e.annotation_by_race,
                        e.interceptions,
                        e.sachs,
                        e.conversions
                        FROM jugador_estadistica je
                        INNER JOIN jugador j ON (je.id_jugador = j.id) 
                        INNER JOIN usuario u ON (j.id = u.id_jugador)
                        INNER JOIN equipo eq ON (eq.id = je.id_equipo)
                        INNER JOIN estadistica e ON (e.id = je.id_estadistica)
                        INNER JOIN level l ON (l.id = j.id_level)
                        WHERE je.id_jugador = ? AND eq.id_status = 1';
        $idJugador = $app->request()->params('idJugador');
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

/* Obtener equipor por jugador*/
$app->get('/getTeams', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        //Creación de level.
        $createEquipo = 'SELECT id, nombre, fotografia, fecha_ult_modificacion as fecha FROM equipo WHERE id_status = 1';
        $sthEquipo = $db->prepare($createEquipo);
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

$app->get('/getTeamById', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        //Creación de level.
        $createEquipo = 'SELECT id, nombre, fotografia, fecha_ult_modificacion as fecha FROM equipo WHERE id = ? AND id_status = 1';
        $idEquipo = $app->request()->params('id');
        $sthEquipo = $db->prepare($createEquipo);
        $sthEquipo->bindParam(1, $idEquipo, PDO::PARAM_INT);
        $sthEquipo->execute();
        $rows = $sthEquipo->fetchAll(PDO::FETCH_ASSOC);
        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $rows[0];
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

/* Crear equipo*/
$app->post('/createTeam', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $db->beginTransaction();
        $idEstatusActivo = 1;
        //Creación de level.
        $createEquipo = 'INSERT INTO equipo (`id_status`, `nombre`, `fecha_ult_modificacion`, `fotografia`) VALUES (1, ?, now(), ?)';
        $nombre = $data['nombre'];
        $fotografia = $data['fotografia'];
        $sthEquipo = $db->prepare($createEquipo);
        $sthEquipo->bindParam(1, $nombre, PDO::PARAM_STR);
        $sthEquipo->bindParam(2, $fotografia, PDO::PARAM_STR);
        $sthEquipo->execute();
        $idEquipo = $db->lastInsertId();

        //Commit exitoso de transacción
        $db->commit();

        /*$fcm = new FCMNotification();

        $token = "f99ERxWzZLM:APA91bG5U5zsltA6rObvRz0K9Lu7N0r1cds6kRVt-d_w1c1whh8nFdYtfmZVehVGMLFA-J_bXh-TXL_eCUYV_Q6GHY5R_AQahLf6r4ow-tAjdJ2Zpzx-pFZ-24KpSIe8eCHznJqrziyo";
        $title = "Notification title";
        $body = "Hello I am from Your php server";
        $notification = array('title' =>$title , 'body' => $body, 'sound' => 'default');
        $arrayToSend = array('to' => $token, 'notification' => $notification,'priority'=>'high');

        $return = $fcm->sendData($arrayToSend);*/

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
$app->post('/updateTeam', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $db->beginTransaction();
        //Creación de level.UPDATE `futbol_americano_v1`.`equipo` SET `nombre` = 'sdfsds' WHERE (`id` = '1');
        $updateEquipo = 'UPDATE equipo SET nombre = ?, fecha_ult_modificacion = now(), id_status = ?, fotografia = ? WHERE id = ?';
        $nombre = $data['nombre'];
        $idEquipo = $data['idEquipo'];
        $idEstatus = $data['idEstatus'];
        $fotografia = $data['fotografia'];
        $sthEquipo = $db->prepare($updateEquipo);
        $sthEquipo->bindParam(3, $fotografia, PDO::PARAM_STR);
        $sthEquipo->bindParam(4, $idEquipo, PDO::PARAM_INT);
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
$app->post('/deleteTeam', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $db->beginTransaction();
        //Creación de level.UPDATE `futbol_americano_v1`.`equipo` SET `nombre` = 'sdfsds' WHERE (`id` = '1');
        $updateEquipo = 'UPDATE equipo SET fecha_ult_modificacion = now(), id_status = 3 WHERE id = ?';
        $idEquipo = $data['idEquipo'];
        $sthEquipo = $db->prepare($updateEquipo);
        $sthEquipo->bindParam(1, $idEquipo, PDO::PARAM_INT);
        $sthEquipo->execute();

        //Al eliminar el equipo 
        $selectEstadisticas = 'SELECT e.id FROM estadistica e
                               INNER JOIN jugador_estadistica je ON (je.id_estadistica = e.id) WHERE je.id_equipo = ?';
        $sthEquipoSelect = $db->prepare($selectEstadisticas);
        $sthEquipoSelect->bindParam(1, $idEquipo, PDO::PARAM_INT);
        $sthEquipoSelect->execute();

        $rows = $sthEquipoSelect->fetchAll(PDO::FETCH_OBJ);

        for ($i=0; $i < count($rows); $i++) { 
            $tempID = $rows[$i]->id;

            //Al eliminar el equipo 
            $deleteEstadisticas = 'DELETE FROM jugador_estadistica WHERE id_equipo = ?';
            $sthEquipoDelete = $db->prepare($deleteEstadisticas);
            $sthEquipoDelete->bindParam(1, $idEquipo, PDO::PARAM_INT);
            $sthEquipoDelete->execute();

            //Al eliminar el equipo 
            $deleteEstadistica = 'DELETE FROM estadistica WHERE id = ?';
            $sthEquipoDeleteEst = $db->prepare($deleteEstadistica);
            $sthEquipoDeleteEst->bindParam(1, $tempID, PDO::PARAM_INT);
            $sthEquipoDeleteEst->execute();            
        }

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

/* Delete equipo a un jugador*/
$app->post('/removeTeamFromPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        $db->beginTransaction();

        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $idEquipo = $data['idEquipo'];
        $idJugador = $data['idJugador'];

        //Al eliminar el equipo 
        $selectEstadisticas = 'SELECT e.id FROM estadistica e
                               INNER JOIN jugador_estadistica je ON (je.id_estadistica = e.id) 
                               WHERE je.id_equipo = ? AND je.id_jugador = ?';
        $sthEquipoSelect = $db->prepare($selectEstadisticas);
        $sthEquipoSelect->bindParam(1, $idEquipo, PDO::PARAM_INT);
        $sthEquipoSelect->bindParam(2, $idJugador, PDO::PARAM_INT);
        $sthEquipoSelect->execute();

        $rows = $sthEquipoSelect->fetchAll(PDO::FETCH_OBJ);

        for ($i=0; $i < count($rows); $i++) { 
            $tempID = $rows[$i]->id;

            //Al eliminar el equipo 
            $deleteEstadisticas = 'DELETE FROM jugador_estadistica WHERE id_equipo = ? AND id_jugador = ?';
            $sthEquipoDelete = $db->prepare($deleteEstadisticas);
            $sthEquipoDelete->bindParam(1, $idEquipo, PDO::PARAM_INT);
            $sthEquipoDelete->bindParam(2, $idJugador, PDO::PARAM_INT);
            $sthEquipoDelete->execute();

            //Al eliminar el equipo 
            $deleteEstadistica = 'DELETE FROM estadistica WHERE id = ?';
            $sthEquipoDeleteEst = $db->prepare($deleteEstadistica);
            $sthEquipoDeleteEst->bindParam(1, $tempID, PDO::PARAM_INT);
            $sthEquipoDeleteEst->execute();            
        }

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

/* Obtener equipor por jugador que aun no tiene asignados*/
$app->get('/getTeamsNotAsigned', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        //Creación de level.
        $createEquipo = 'SELECT e.id, e.nombre FROM equipo e
                         WHERE e.id NOT IN (SELECT je.id_equipo 
                         FROM jugador_estadistica je WHERE je.id_jugador = ?)';
        $idJugador = $app->request()->params('idJugador');
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