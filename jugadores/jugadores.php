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


/* Usando GET para consultar los autos */
$app->post('/createPlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $db->beginTransaction();
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $querieVerifyUser = 'SELECT * FROM usuario WHERE LOWER(username) = LOWER(?)';
        $sth = $db->prepare($querieVerifyUser);
        $sth->bindParam(1, $data['username'], PDO::PARAM_STR);
        $sth->execute();
        $rows = $sth->fetchAll(PDO::FETCH_ASSOC);

        if(empty($rows)){
            //Creación de jugador simple.
            $createJugador = 'INSERT INTO jugador (`id_level`, `fotografia`, `sale`, `rama`) VALUES (?,?,?,?)';
            $fotografia = $data['fotografia'];
            $sale = $data['sale'];
            $rama = $data['rama'];
            $sthJugador = $db->prepare($createJugador);
            $sthJugador->bindParam(1, $data['idLevel'], PDO::PARAM_INT);
            $sthJugador->bindParam(2, $fotografia, PDO::PARAM_STR);
            $sthJugador->bindParam(3, $sale, PDO::PARAM_STR);//Se usa string para datos numericos
            $sthJugador->bindParam(4, $rama, PDO::PARAM_STR);
            $sthJugador->execute();
            $idJugador = $db->lastInsertId();

            //Creación de objeto jugador-estadistica
            $equipos = $data['equipos'];
            for ($i=0; $i < count($equipos); $i++) { 
                //Creación de estadística en ceros.
                $createEstadistica = 'INSERT INTO 
                                      estadistica (`touch_pass`, `annotation_by_race`, `annotation_by_pass`, 
                                      `interceptions`, `sachs`, `conversions`) VALUES (0,0,0,0,0,0);';
                $sthEstadistica = $db->prepare($createEstadistica);
                $sthEstadistica->execute();
                $idEstadistica = $db->lastInsertId();

                $createJugadorEstadistica = 'INSERT INTO jugador_estadistica (`id_equipo`, `id_jugador`, `id_estadistica`) VALUES (?,?,?)';
                $sthJugadorEstadistica = $db->prepare($createJugadorEstadistica);
                $sthJugadorEstadistica->bindParam(1, $equipos[$i], PDO::PARAM_INT);
                $sthJugadorEstadistica->bindParam(2, $idJugador, PDO::PARAM_INT);
                $sthJugadorEstadistica->bindParam(3, $idEstadistica, PDO::PARAM_INT);
                $sthJugadorEstadistica->execute();
                $idJugadorEstadistica = $db->lastInsertId();
            }

            //Creación de usuario con datos de jugador
            $createUsuario = 'INSERT INTO usuario 
            (`id_rol`, `id_status`, `id_jugador`, `username`, `password`, `nombre`, `apellido_paterno`, `apellido_materno`) 
            VALUES (?,?,?,?,MD5(?),?,?,?)';
            $idRol = 2;//Rol jugador
            $idStatus = 1;//Estatus Activo
            $username = $data['username'];
            $password = $data['password'];
            $nombre = $data['nombre'];
            $apellidoPaterno = $data['apellido_paterno'];
            $apellidoMaterno = $data['apellido_materno'];
            $passwordEncriptado = dec_enc('encrypt',$password);
            $sthUsuario = $db->prepare($createUsuario);
            $sthUsuario->bindParam(1, $idRol, PDO::PARAM_INT);
            $sthUsuario->bindParam(2, $idStatus, PDO::PARAM_INT);
            $sthUsuario->bindParam(3, $idJugador, PDO::PARAM_INT);
            $sthUsuario->bindParam(4, $username, PDO::PARAM_STR);
            $sthUsuario->bindParam(5, $passwordEncriptado, PDO::PARAM_STR);
            $sthUsuario->bindParam(6, $nombre, PDO::PARAM_STR);
            $sthUsuario->bindParam(7, $apellidoPaterno, PDO::PARAM_STR);
            $sthUsuario->bindParam(8, $apellidoMaterno, PDO::PARAM_STR);
            $sthUsuario->execute();
            $idUsuario = $db->lastInsertId();

            //Commit exitoso de transacción
            $db->commit();

            $response["status"] = "A";
            $response["description"] = "Exitoso";
            $response["idTransaction"] = time();
            $response["parameters"] = $idUsuario;
            $response["timeRequest"] = date("Y-m-d H:i:s");
            echoResponse(200, $response);
        }else{
            $response["status"] = "I";
            $response["description"] = "El usuario ".$data['username']." no se encuentra disponible, intente nuevamente";
            $response["idTransaction"] = time();
            $response["parameters"] = [];
            $response["timeRequest"] = date("Y-m-d H:i:s");
            echoResponse(200, $response);
        }
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

/* Cambio de contraseña por jugador */
$app->post('/changePassword', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        $sqlExist = 'SELECT * FROM usuario WHERE password = MD5(?) AND id_jugador = ?';
        $password = $data['password'];
        $idJugador = $data['idJugador'];
        $newPassword = $data['newPassword'];
        $passwordEncriptado = dec_enc('encrypt',$password);
        $sthSqlExist = $db->prepare($sqlExist);
        $sthSqlExist->bindParam(1, $passwordEncriptado, PDO::PARAM_STR);
        $sthSqlExist->bindParam(2, $idJugador, PDO::PARAM_INT);
        $sthSqlExist->execute();
        $rows = $sthSqlExist->fetchAll(PDO::FETCH_ASSOC);

        if(!empty($rows)){

            $sqlUpdatePassword = 'UPDATE usuario SET password = MD5(?) WHERE id_jugador = ?';
            $newPasswordEncriptado = dec_enc('encrypt',$newPassword);
            $sthSqlUpdatePassword = $db->prepare($sqlUpdatePassword);
            $sthSqlUpdatePassword->bindParam(1, $newPasswordEncriptado, PDO::PARAM_STR);
            $sthSqlUpdatePassword->bindParam(2, $idJugador, PDO::PARAM_INT);
            $sthSqlUpdatePassword->execute();
            $rows = $sthSqlUpdatePassword->fetchAll(PDO::FETCH_ASSOC);

            $response["status"] = "A";
            $response["description"] = "Exitoso";
            $response["idTransaction"] = time();
            $response["parameters"] = $rows;
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

/* update jugador */
$app->post('/updatePlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $db->beginTransaction();
        $body = $app->request->getBody();
        $data = json_decode($body, true);

        //Actualización de usuario con datos de jugador
        $updateUsuario = 'UPDATE usuario SET nombre = ?, apellido_paterno = ?, apellido_materno = ? WHERE id_jugador = ?';
        $nombre = $data['nombre'];
        $apellidoPaterno = $data['apellido_paterno'];
        $apellidoMaterno = $data['apellido_materno'];
        $idJugador = $data['idJugador'];
        $sthUsuario = $db->prepare($updateUsuario);
        $sthUsuario->bindParam(4, $idJugador, PDO::PARAM_INT);
        $sthUsuario->bindParam(1, $nombre, PDO::PARAM_STR);
        $sthUsuario->bindParam(2, $apellidoPaterno, PDO::PARAM_STR);
        $sthUsuario->bindParam(3, $apellidoMaterno, PDO::PARAM_STR);
        $sthUsuario->execute();

        //Actualización de jugador simple.
        $updateJugador = 'UPDATE jugador SET fotografia = ?, sale = ?, rama = ?, id_level = ? WHERE id = ?';
        $fotografia = $data['fotografia'];
        $sale = $data['sale'];
        $rama = $data['rama'];
        $idLevel = $data['idLevel'];
        $sthJugador = $db->prepare($updateJugador);
        $sthJugador->bindParam(1, $fotografia, PDO::PARAM_STR);
        $sthJugador->bindParam(2, $sale, PDO::PARAM_STR);//Se usa string para datos numericos
        $sthJugador->bindParam(3, $rama, PDO::PARAM_STR);
        $sthJugador->bindParam(4, $idLevel, PDO::PARAM_INT);
        $sthJugador->bindParam(5, $idJugador, PDO::PARAM_INT);
        $sthJugador->execute();

        $equipos = $data['equipos'];
        for ($i=0; $i < count($equipos); $i++) { 
            //Creación de estadística en ceros.
            $createEstadistica = 'INSERT INTO 
                                    estadistica (`touch_pass`, `annotation_by_race`, `annotation_by_pass`, 
                                    `interceptions`, `sachs`, `conversions`) VALUES (0,0,0,0,0,0);';
            $sthEstadistica = $db->prepare($createEstadistica);
            $sthEstadistica->execute();
            $idEstadistica = $db->lastInsertId();

            $createJugadorEstadistica = 'INSERT INTO jugador_estadistica (`id_equipo`, `id_jugador`, `id_estadistica`) VALUES (?,?,?)';
            $sthJugadorEstadistica = $db->prepare($createJugadorEstadistica);
            $sthJugadorEstadistica->bindParam(1, $equipos[$i], PDO::PARAM_INT);
            $sthJugadorEstadistica->bindParam(2, $idJugador, PDO::PARAM_INT);
            $sthJugadorEstadistica->bindParam(3, $idEstadistica, PDO::PARAM_INT);
            $sthJugadorEstadistica->execute();
            $idJugadorEstadistica = $db->lastInsertId();
        }

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

/* delete jugador */
$app->post('/deletePlayer', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        
        $db->beginTransaction();
        $body = $app->request->getBody();
        $data = json_decode($body, true);
        $idJugador = $data['idJugador'];

        $selectEstadisticas = 'SELECT e.id FROM estadistica e
                               INNER JOIN jugador_estadistica je ON (je.id_estadistica = e.id) WHERE je.id_jugador = ?';
        $sthEquipoSelect = $db->prepare($selectEstadisticas);
        $sthEquipoSelect->bindParam(1, $idJugador, PDO::PARAM_INT);
        $sthEquipoSelect->execute();

        $rows = $sthEquipoSelect->fetchAll(PDO::FETCH_OBJ);

        for ($i=0; $i < count($rows); $i++) { 
            $tempID = $rows[$i]->id;

            //Al eliminar el jugador 
            $deleteEstadisticas = 'DELETE FROM jugador_estadistica WHERE id_jugador = ?';
            $sthEquipoDelete = $db->prepare($deleteEstadisticas);
            $sthEquipoDelete->bindParam(1, $idJugador, PDO::PARAM_INT);
            $sthEquipoDelete->execute();

            //Al eliminar el jugador 
            $deleteEstadistica = 'DELETE FROM estadistica WHERE id = ?';
            $sthEquipoDeleteEst = $db->prepare($deleteEstadistica);
            $sthEquipoDeleteEst->bindParam(1, $tempID, PDO::PARAM_INT);
            $sthEquipoDeleteEst->execute();            
        }
        //Se elimina usuario
        $deleteJugadorU = 'DELETE FROM usuario WHERE id_jugador = ?';
        $sthJugadorUDelete = $db->prepare($deleteJugadorU);
        $sthJugadorUDelete->bindParam(1, $idJugador, PDO::PARAM_INT);
        $sthJugadorUDelete->execute();

        //Al eliminar el jugador 
        $deleteJugador = 'DELETE FROM jugador WHERE id = ?';
        $sthJugadorDelete = $db->prepare($deleteJugador);
        $sthJugadorDelete->bindParam(1, $idJugador, PDO::PARAM_INT);
        $sthJugadorDelete->execute();

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

/* Obtener jugadores*/
$app->get('/getPlayers', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        //Creación de level.
        $getLevels = 'SELECT 
                    u.id_jugador,
                    j.fotografia,
                    concat(u.nombre," ", u.apellido_paterno," ", u.apellido_materno) as nombreCompleto,
                    j.rama
                    FROM usuario u
                    INNER JOIN jugador j ON (u.id_jugador = j.id)
                    WHERE u.id_jugador IS NOT NULL';
        $sth = $db->prepare($getLevels);
        $sth->execute();
        $rows = $sth->fetchAll(PDO::FETCH_ASSOC);

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

/* Obtener jugador*/
$app->get('/getPlayerById', function() use ($app){
    try{
        $response = array();
        $dbHandler = new DbHandler();
        $db = $dbHandler->getConnection();
        //Creación de level.
        $getLevels = 'SELECT 
                        u.nombre,
                        u.apellido_paterno,
                        u.apellido_materno,
                        j.rama,
                        l.id as idLevel,
                        l.level,
                        j.sale,
                        j.fotografia,
                        j.id
                        FROM usuario u
                        INNER JOIN jugador j ON (u.id_jugador = j.id)
                        INNER JOIN level l ON (l.id = j.id_level)
                        WHERE u.id_jugador = ?';

        $user = $app->request()->params('id');
        $sth = $db->prepare($getLevels);
        $sth->bindParam(1, $user, PDO::PARAM_STR);
        $sth->execute();
        $rows = $sth->fetchAll(PDO::FETCH_ASSOC);

        if(count($rows)>0){
            $response["status"] = "A";
            $response["description"] = "Exitoso";
            $response["idTransaction"] = time();
            $response["parameters"] = $rows[0];
            $response["timeRequest"] = date("Y-m-d H:i:s");
            echoResponse(200, $response);
        }else{
            $response["status"] = "I";
            $response["description"] = "El usuario no existe en la base de datos";
            $response["idTransaction"] = time();
            $response["parameters"] = [];
            $response["timeRequest"] = date("Y-m-d H:i:s");
            echoResponse(200, $response);
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