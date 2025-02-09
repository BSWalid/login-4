<?php 
session_start(); 
if(isset($_SESSION['current_user'])) header('Location: profile.php');
if(!empty($_SESSION['errors'])) $errors = $_SESSION['errors'];
if(!empty($_SESSION['old'])) $old = $_SESSION['old'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="preconnect" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet"> 

    <title>Form handling in PHP</title>
    <style>
        body{
            font-family: 'Roboto', sans-serif;
        }
        fieldset {
            width: 1000px; 
            margin: auto;
            display: block;
            position: relative;
            border-radius: 5px;
        }
        fieldset form input {
            display: block;
            width: 100%;
            height: 80px;
            margin: 20px auto;
            font-size: 22px;
            padding: 10px;
            box-sizing: border-box;
        }
        fieldset form button {
            position: relative;
            float: right;
            height: 60px;
            width: 20%;
            font-size: 22px;
        }
        .is-invalid {
            color: #FF4430;
        }

        a{
            

            font-family: 'Roboto';
            text-decoration: none;
            font-weight: bold;
            font-size: 25px;
            

        }
        a:hover{

            color:#FF4430 ;
        }
    </style>
</head>
<body>
    <fieldset>
        <legend><h1>Login new User</h1></legend>
        <form action="src/Auth/login.php" method="POST">
            <input 
            type="text" 
            name="username" 
            placeholder="Username or Email"
            value="<?php if(isset($old['username'])) echo $old['username']; ?>"
            >
            <?php
            if(isset($errors['username'])) {
                foreach($errors['username'] as $error) {
                    ?>
                    <small class="is-invalid"><?= $error ?></small>
                    <?php
                }
            } 
            ?>
            <input type="password" name="password" placeholder="Password">
            <?php 
             if(isset($errors['password'])) {
                foreach($errors['password'] as $error) {
                    ?>
                    <small class="is-invalid"><?= $error ?></small>
                    <?php
                }
            } ?>

            <a href="./register_view.php">Register your self</a>
            <button type="submit">Login</button>
        </form>
    </fieldset>


    

    <pre><code>
    <?php session_destroy(); ?>
    </code></pre>
</body>
</html>