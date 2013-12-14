<?php
    
    error_reporting( E_ALL );

    require 'zxcvbn/init.php';
    require 'passwords.php';

    $fields = array( 'entropy', 'crack_time_seconds', 'crack_time_display', 'score' );

    $pass = 0;
    $fail = 0;

    foreach ( $passwords as $password )
    {
        #if ( $password['input'] !== 'coRrecth0rseba++ery9.23.2007staple$' ) continue;
        #END (pass: 34 / fail: 1)..

        echo 'INPUT: ' . $password['input'] . PHP_EOL;

        $zxcvbn = zxcvbn( $password['input'] );

        $OK = TRUE;

        foreach ( $fields as $field )
        {
            $comparison = $zxcvbn[$field];

            $diff = ( $password[$field] !== $comparison );

            printf( 
                '%s for %s: Expected %s, Returned %s' . PHP_EOL, 
                ( $diff ? 'FAIL' : 'PASS' ),
                strtoupper( $field ),
                $password[$field], 
                $comparison
            );

            if ( $diff ) $OK = FALSE;
        }

        if ( $OK )
        {
            $pass +=1;
        }
        else
        {
            $fail +=1;
        }

        echo 'OUTCOME: ' . ( $OK ? 'PASS' : 'FAIL' ) . PHP_EOL;
        echo '==========' . PHP_EOL;
    };

    echo PHP_EOL . PHP_EOL;
    echo sprintf( 'END (pass: %d / fail: %d).', $pass, $fail );
    echo PHP_EOL;
?>