This is a PHP port of Ryan Pearl's ([@rpearl](https://github.com/rpearl/python-zxcvbn)) 
python-zxcvbn port which itself is a port of Dan Wheeler's ([@lowe](https://github.com/lowe/zxcvbn)) zxcvbn, 
which is a JavaScript password strength generator. 

Refer to the original JavaScript (well, actually CoffeeScript) implementation 
which can be found at: https://github.com/lowe/zxcvbn

NB: This is Quick 'n Dirty Port<sup>TM</sup> to PHP, as a starting point so I could 
understand how zxcvbn worked. You probably don't want to use this with production code, yet.

To see it in action, run:
`php example.php` 