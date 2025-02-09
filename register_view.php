<?php 
session_start(); 
if(!empty($_SESSION['errors'])) $errors = $_SESSION['errors'];
if(!empty($_SESSION['old'])) $old = $_SESSION['old'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <style>
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
    </style>
</head>
<body>
    <fieldset>
        <legend><h1>Register your self as new user</h1></legend>
        <form action="src/Auth/register.php" method="POST">
            <input  type="text" name="username" placeholder="Username"
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


            <input type="password" name="password_confirmation" placeholder="Re write your password">
            <?php   
             if(isset($errors['password'])) {
                foreach($errors['password'] as $error) {
                    ?>
                    <small class="is-invalid"><?= $error ?></small>
                    <?php
                }
            } ?>

            <input type="email" name="email" placeholder="Please Provide your email">
                        <?php   
                        if(isset($errors['email'])) {
                            foreach($errors['email'] as $error) {
                                ?>
                                <small class="is-invalid"><?= $error ?></small>
                                <?php
                            }
                        } ?>



            <input type="text" name="name" placeholder="Please provide your full name">
                        <?php   
                        if(isset($errors['name'])) {
                            foreach($errors['name'] as $error) {
                                ?>
                                <small class="is-invalid"><?= $error ?></small>
                                <?php
                            }
                        } ?>







            <button type="submit">Register</button>
        </form>
    </fieldset>

    <pre><code>
    <?php session_destroy(); ?>
    </code></pre>
</body>
</html>