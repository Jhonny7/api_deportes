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


/* Usando GET para consultar los autos */
$app->get('/getUsuarios', function(){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        //$resultado = $db->getRadios();
        $sql = 'SELECT * FROM usuario';

        $array = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);

        $response["status"] = "A";
        $response["description"] = "Exitoso";
        $response["idTransaction"] = time();
        $response["parameters"] = $array;
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

/* Cambio de contraseña por jugador */
$app->post('/changePassword', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $sqlExist = 'SELECT * FROM usuario WHERE password = MD5(?) AND id = ?';
        $password = $data['password'];
        $idUsuario = $data['idUsuario'];
        $newPassword = $data['newPassword'];
        $passwordEncriptado = dec_enc('encrypt',$password);
        $sthSqlExist = $db->prepare($sqlExist);
        $sthSqlExist->bindParam(1, $passwordEncriptado, PDO::PARAM_STR);
        $sthSqlExist->bindParam(2, $idUsuario, PDO::PARAM_INT);
        $sthSqlExist->execute();
        $rows = $sthSqlExist->fetchAll(PDO::FETCH_ASSOC);

        if(!empty($rows)){

            $sqlUpdatePassword = 'UPDATE usuario SET password = MD5(?) WHERE id = ?';
            $newPasswordEncriptado = dec_enc('encrypt',$newPassword);
            $sthSqlUpdatePassword = $db->prepare($sqlUpdatePassword);
            $sthSqlUpdatePassword->bindParam(1, $newPasswordEncriptado, PDO::PARAM_STR);
            $sthSqlUpdatePassword->bindParam(2, $idUsuario, PDO::PARAM_INT);
            $sthSqlUpdatePassword->execute();
            $rows = $sthSqlUpdatePassword->fetchAll(PDO::FETCH_ASSOC);

            $querieNotifi = 'SELECT * FROM usuario WHERE id_rol = 1';
            $sthAdmin = $db->prepare($querieNotifi);
            $sthAdmin->execute();
            $rowsAdmin = $sthAdmin->fetchAll(PDO::FETCH_ASSOC);

            $envio = "";
            if($rowsAdmin[0] != null && $rowsAdmin[0]['token'] != null){
                $envio = "Se envia notificacion";
                $token = $rowsAdmin[0]['token'];

                $fcm = new FCMNotification();
                $title = "Cambio de contraseña";
                $body = "Que tal ".$rowsAdmin[0]['nombre'].", te informamos que ".$rows[0]['nombre']." ha actualizado su contraseña.";
                $notification = array('title' =>$title , 'body' => $body, 'sound' => 'default');
                $arrayToSend = array('to' => $token, 'notification' => $notification,'priority'=>'high');

                $return = $fcm->sendData($arrayToSend);
            }else{
                $envio = "No se envia notificacion";
            }

            $response["status"] = "A";
            $response["description"] = "Exitoso";
            $response["idTransaction"] = time();
            $response["parameters"] = $enviothis.change();;
            $response["timeRequest"] = date("Y-m-d H:i:s");

            echoResponse(200, $response);
        }else{
            $response["status"] = "I";
            $response["description"] = "Password incorrecto favor de verificar correctamente";
            $response["idTransaction"] = time();
            $response["parameters"] = [];
            $response["timeRequest"] = date("Y-m-d H:i:s");

            echoResponse(400, $response);
        }
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