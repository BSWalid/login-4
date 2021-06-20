<?php session_start();
require '../../config/database.php';
require '../Exceptions/errors.php';
// handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    $passwordC = trim($_POST['password_confirmation']);
    $name = trim($_POST['name']);
    $email = trim($_POST['email']);
    $old = [];

    // validate
    if (!$username) {
        add_error_to_session('username', 'you must provide a username');
    } else {
        if(!preg_match("/^[a-zA-Z0-9]+$/", $username)) {
            $old['username'] = $username;
            add_error_to_session('username', 'Invalid username!');
        }
    }


    if (empty($password)) {
        add_error_to_session('password', 'you must provide a password');
    }else
    {  if(strcmp($password,$passwordC))
         add_error_to_session('password', 'password dont match');
       
    } 
    

    


    if(!empty($_SESSION['errors'])) {
        header('Location: ' . $_SERVER['HTTP_REFERER']);
    } else {

        
        
        // check if username or email is unique
        $query = 'SELECT * FROM users WHERE username="'. $username.'"';



        $resultUsername = mysqli_query($con, $query);

        if(mysqli_num_rows($resultUsername) ) 
         add_error_to_session('username', 'this user exist please choose another username');

        else {
            $query = 'Insert into users (username,password,email,name) 
                                  values("'. $username.'",
                                          "'. password_hash($password,PASSWORD_BCRYPT).'",
                                          "'. $email.'",
                                          "'. $name.'");';


            

            mysqli_query($con,$query);
            $user['id'] = mysqli_insert_id($con);
            

            $_SESSION['current_user'] = $user['id'];
            header('Location: ../../profile.php');                             
        }
        if(!empty($_SESSION['errors'])) {
            $_SESSION['old'] = $old;
            header('Location: ' . $_SERVER['HTTP_REFERER']);
        }
    }
}
