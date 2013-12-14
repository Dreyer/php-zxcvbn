This is a PHP port of Dan Wheeler's ([@lowe](https://github.com/lowe/zxcvbn)) zxcvbn, 
which is a JavaScript password strength generator.

NB: You probably don't want to use this with production code, yet. Or without testing yourself. YMMV.

All tests are performed by comparing the output from php-zxcvbn to the output from the JavaScript implementation.

To see it in action, run:
`php test.php` 