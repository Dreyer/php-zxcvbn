<?php
# testing passwords and expected outcomes copied from JavaScript zxcvbn.
# https://dl.dropboxusercontent.com/u/209/zxcvbn/test/index.html
$passwords = array(
    array(
        'input' => 'php-zxcvbn',
        'entropy' => 30.376,
        'crack_time_seconds' => 69674.826,
        'crack_time_display' => '21 hours',
        'score' => 2
    ),
    array(
        'input' => 'zxcvbn',
        'entropy' => 6.845,
        'crack_time_seconds' => 0.006,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'qwER43@!',
        'entropy' => 26.44,
        'crack_time_seconds' => 4551.454,
        'crack_time_display' => '3 hours',
        'score' => 1
    ),
    array(
        'input' => 'Tr0ub4dour&3',
        'entropy' => 30.435,
        'crack_time_seconds' => 72600.71,
        'crack_time_display' => '22 hours',
        'score' => 2
    ),
    array(
        'input' => 'correcthorsebatterystaple',
        'entropy' => 45.212,
        'crack_time_seconds' => 2037200406.475,
        'crack_time_display' => '65 years',
        'score' => 4
    ),
    array(
        'input' => 'coRrecth0rseba++ery9.23.2007staple$',
        'entropy' => 66.018,
        'crack_time_seconds' => 3734821476714185.0,
        'crack_time_display' => 'centuries',
        'score' => 4
    ),
    array(
        'input' => 'D0g..................',
        'entropy' => 20.678,
        'crack_time_seconds' => 83.873,
        'crack_time_display' => '3 minutes',
        'score' => 0
    ),
    array(
        'input' => 'abcdefghijk987654321',
        'entropy' => 11.951,
        'crack_time_seconds' => 0.198,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'neverforget13/3/1997',
        'entropy' => 32.628,
        'crack_time_seconds' => 331974.586,
        'crack_time_display' => '5 days',
        'score' => 2
    ),
    array(
        'input' => '1qaz2wsx3edc',
        'entropy' => 19.314,
        'crack_time_seconds' => 32.594,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'temppass22',
        'entropy' => 24.056,
        'crack_time_seconds' => 871.977,
        'crack_time_display' => '16 minutes',
        'score' => 1
    ),
    array(
        'input' => 'briansmith',
        'entropy' => 4.322,
        'crack_time_seconds' => 0.001,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'briansmith4mayor',
        'entropy' => 18.64,
        'crack_time_seconds' => 20.43,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'password1',
        'entropy' => 2.0,
        'crack_time_seconds' => 0.0,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'viking',
        'entropy' => 7.531,
        'crack_time_seconds' => 0.009,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'thx1138',
        'entropy' => 7.426,
        'crack_time_seconds' => 0.009,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'ScoRpi0ns',
        'entropy' => 21.237,
        'crack_time_seconds' => 123.562,
        'crack_time_display' => '4 minutes',
        'score' => 1
    ),
    array(
        'input' => 'do you know',
        'entropy' => 20.257,
        'crack_time_seconds' => 62.658,
        'crack_time_display' => '3 minutes',
        'score' => 0
    ),
    array(
        'input' => 'ryanhunter2000',
        'entropy' => 14.506,
        'crack_time_seconds' => 1.164,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'rianhunter2000',
        'entropy' => 22.673,
        'crack_time_seconds' => 334.305,
        'crack_time_display' => '7 minutes',
        'score' => 1
    ),
    array(
        'input' => 'asdfghju7654rewq',
        'entropy' => 29.782,
        'crack_time_seconds' => 46159.451,
        'crack_time_display' => '14 hours',
        'score' => 2
    ),
    array(
        'input' => 'AOEUIDHG&*()LS_',
        'entropy' => 33.254,
        'crack_time_seconds' => 512056.356,
        'crack_time_display' => '7 days',
        'score' => 2
    ),
    array(
        'input' => '12345678',
        'entropy' => 1.585,
        'crack_time_seconds' => 0.0,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'defghi6789',
        'entropy' => 12.607,
        'crack_time_seconds' => 0.312,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'rosebud',
        'entropy' => 7.937,
        'crack_time_seconds' => 0.012,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'Rosebud',
        'entropy' => 8.937,
        'crack_time_seconds' => 0.025,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'ROSEBUD',
        'entropy' => 8.937,
        'crack_time_seconds' => 0.025,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'rosebuD',
        'entropy' => 8.937,
        'crack_time_seconds' => 0.025,
        'crack_time_display' => 'instant',
        'score' => 0
    ),
    array(
        'input' => 'ros3bud99',
        'entropy' => 21.154,
        'crack_time_seconds' => 116.645,
        'crack_time_display' => '3 minutes',
        'score' => 1
    ),
    array(
        'input' => 'r0s3bud99',
        'entropy' => 21.154,
        'crack_time_seconds' => 116.645,
        'crack_time_display' => '3 minutes',
        'score' => 1
    ),
    array(
        'input' => 'R0$38uD99',
        'entropy' => 25.076,
        'crack_time_seconds' => 1768.9,
        'crack_time_display' => '31 minutes',
        'score' => 1
    ),
    array(
        'input' => 'verlineVANDERMARK',
        'entropy' => 26.293,
        'crack_time_seconds' => 4111.115,
        'crack_time_display' => '3 hours',
        'score' => 1
    ),
    array(
        'input' => 'eheuczkqyq',
        'entropy' => 42.813,
        'crack_time_seconds' => 386330069.466,
        'crack_time_display' => '14 years',
        'score' => 4
    ),
    array(
        'input' => 'rWibMFACxAUGZmxhVncy',
        'entropy' => 116.604,
        'crack_time_seconds' => 6.311342330065347e+30,
        'crack_time_display' => 'centuries',
        'score' => 4
    ),
    array(
        'input' => 'Ba9ZyWABu99[BK#6MBgbH88Tofv)vs$w',
        'entropy' => 167.848,
        'crack_time_seconds' => 1.6834916094728833e+46,
        'crack_time_display' => 'centuries',
        'score' => 4
    )
);
?>