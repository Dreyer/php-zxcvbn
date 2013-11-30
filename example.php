<?php
    
    error_reporting( E_ALL );

    require 'zxcvbn/main.php';

    foreach ( file( 'tests.txt' ) as $line )
    {
        $password = trim( $line );
        $strength = password_strength( $password );

        echo sprintf( 'password: %s' . PHP_EOL, $strength['password'] );
        echo sprintf( 'entropy: %s' . PHP_EOL, $strength['entropy'] );
        echo sprintf( 'crack_time: %s' . PHP_EOL, $strength['crack_time'] );
        echo sprintf( 'crack_time_display: %s' . PHP_EOL, $strength['crack_time_display'] );
        echo sprintf( 'score: %s' . PHP_EOL, $strength['score'] );
        echo sprintf( 'calc_time: %s' . PHP_EOL, $strength['calc_time'] );

        echo PHP_EOL . PHP_EOL;
    };
?>