<?php

#namespace zxcbn\scoring;

# Returns binomial coefficient (n choose k).
# http://blog.plover.com/math/choose.html
function binom( $n, $k )
{
    if ( $k > $n )
    {
        return 0;
    };

    if ( $k == 0 )
    {
        return 1;
    };

    $result = 1;
    
    foreach ( range( 1, $k + 1 ) as $denom )
    {
        $result *= $n;
        $result /= $denom;
        $n -= 1;
    };

    return $result;
};

# Returns logarithm of n in base 2.
function lg( $n )
{
    return log( $n, 2 );
};

# ------------------------------------------------------------------------------
# minimum entropy search -------------------------------------------------------
# ------------------------------------------------------------------------------
#
# takes a list of overlapping matches, returns the non-overlapping sublist with
# minimum entropy. O(nm) dp alg for length-n password with m candidate matches.
# ------------------------------------------------------------------------------
function get( $a, $i )
{
    return ( ( $i < 0 || $i >= count( $a ) ) ? 0 : $a[$i] );
};


# Returns minimum entropy
# Takes a list of overlapping matches, returns the non-overlapping sublist with
# minimum entropy. O(nm) dp alg for length-n password with m candidate matches.

function minimum_entropy_match_sequence( $password, $matches )
{
    $up_to_k = array();

    # for the optimal sequence of matches up to k, holds the final match (match['j'] == k). null means the sequence ends
    # without a brute-force character.
    $backpointers = array();

    $bruteforce_cardinality = calc_bruteforce_cardinality( $password ); # e.g. 26 for lowercase

    foreach ( range( 0, strlen( $password ) ) as $k )
    {
        # starting scenario to try and beat: adding a brute-force character to the minimum entropy sequence at k-1.
        $up_to_k[$k] = get( $up_to_k, $k - 1 ) + lg( $bruteforce_cardinality );

        $backpointers[$k] = NULL;

        foreach ( $matches as $match )
        {
            if ( ! isset( $match['j'] ) || $match['j'] != $k )
            {
                continue;
            };

            $i = $match['i']; 
            $j = $match['j'];

            # see if best entropy up to i-1 + entropy of this match is less than the current minimum at j.
            $up_to = get( $up_to_k, $i - 1 );
            $candidate_entropy = $up_to + calc_entropy( $match );
            
            if ( $candidate_entropy < $up_to_k[$j] )
            {
                #print "New minimum: using " + str(match)
                #print "Entropy: " + str(candidate_entropy)
                $up_to_k[$j] = $candidate_entropy;
                $backpointers[$j] = $match;
            };
        };
    };

    # walk backwards and decode the best sequence
    $match_sequence = array();
    $k = strlen( $password ) - 1;

    while ( $k >= 0 )
    {
        $match = $backpointers[$k];

        if ( $match )
        {
            $match_sequence[] = $match;

            $k = $match['i'] - 1;
        }
        else
        {
            $k -= 1;
        };
    };

    $match_sequence = array_reverse( $match_sequence );

    # fill in the blanks between pattern matches with bruteforce "matches"
    # that way the match sequence fully covers the password: match1.j == match2.i - 1 for every adjacent match1, match2.
    $make_bruteforce_match = function( $i, $j ) use ( $password, $bruteforce_cardinality )
    {
        return array(
            'pattern' => 'bruteforce',
            'i' => $i,
            'j' => $j,
            'token' => substr( $password, $i, $j + 1 ),
            'entropy' => lg( pow( $bruteforce_cardinality, $j - $i + 1 ) ),
            'cardinality' => $bruteforce_cardinality,
        );
    };

    $k = 0;
    $match_sequence_copy = array();

    foreach ( $match_sequence as $match )
    {
        $i = $match['i'];
        $j = $match['j'];

        if ( $i - $k > 0 )
        {
            $match_sequence_copy[] = $make_bruteforce_match( $k, $i - 1 );
        };

        $k = $j + 1;

        $match_sequence_copy[] = $match;
    };

    if ( $k < strlen( $password ) )
    {
        $match_sequence_copy[] = $make_bruteforce_match( $k, strlen( $password ) - 1 );
    };

    $match_sequence = $match_sequence_copy;

    # corner case is for an empty password ''
    if ( strlen( $password ) === 0 )
    {
        $min_entropy = 0;
    }
    else
    {
        $min_entropy = $up_to_k[strlen( $password ) - 1];
    };

    $crack_time = entropy_to_crack_time( $min_entropy );

    # final result object
    $result = array(
        'password' => $password,
        'entropy' => round_to_x_digits( $min_entropy, 3 ),
        'match_sequence' => $match_sequence,
        'crack_time' => round_to_x_digits( $crack_time, 3 ),
        'crack_time_display' => display_time( $crack_time ),
        'score' => crack_time_to_score( $crack_time ),
    );

    return $result;
};

# Returns 'number' rounded to 'digits' digits.
function round_to_x_digits( $number, $digits )
{
    return round( $number * pow( 10, $digits ) ) / pow( 10, $digits );
};


# ------------------------------------------------------------------------------
# threat model -- stolen hash catastrophe scenario -----------------------------
# ------------------------------------------------------------------------------
#
# assumes:
# * passwords are stored as salted hashes, different random salt per user.
#   (making rainbow attacks infeasable.)
# * hashes and salts were stolen. attacker is guessing passwords at max rate.
# * attacker has several CPUs at their disposal.
# ------------------------------------------------------------------------------

# for a hash function like bcrypt/scrypt/PBKDF2, 10ms per guess is a safe lower bound.
# (usually a guess would take longer -- this assumes fast hardware and a small work factor.)
# adjust for your site accordingly if you use another hash function, possibly by
# several orders of magnitude!
$SINGLE_GUESS = 0.010;
$NUM_ATTACKERS = 100; # number of cores guessing in parallel.

$SECONDS_PER_GUESS = $SINGLE_GUESS / $NUM_ATTACKERS;


function entropy_to_crack_time( $entropy )
{
    global $SECONDS_PER_GUESS;

    return ( 0.5 * pow( 2, $entropy ) ) * $SECONDS_PER_GUESS; # average, not total
};


function crack_time_to_score( $seconds )
{
    if ( $seconds < pow( 10, 2 ) )
    {
        return 0;
    };

    if ( $seconds < pow( 10, 4 ) )
    {
        return 1;
    };

    if ( $seconds < pow( 10, 6 ) )
    {
        return 2;
    };

    if ( $seconds < pow( 10, 8 ) )
    {
        return 3;
    };

    return 4;
};

# ------------------------------------------------------------------------------
# entropy calcs -- one function per match pattern ------------------------------
# ------------------------------------------------------------------------------

function calc_entropy( $match )
{
    if ( isset( $match['entropy'] ) )
    {
        return $match['entropy'];
    };

    if ( $match['pattern'] === 'repeat' )
    {
        $entropy_func = 'repeat_entropy';
    }
    elseif ( $match['pattern'] === 'sequence' )
    {
        $entropy_func = 'sequence_entropy';
    }
    elseif ( $match['pattern'] === 'digits' )
    {
        $entropy_func = 'digits_entropy';
    }
    elseif ( $match['pattern'] === 'year' )
    {
        $entropy_func = 'year_entropy';
    }
    elseif ( $match['pattern'] === 'date' )
    {
        $entropy_func = 'date_entropy';
    }
    elseif ( $match['pattern'] === 'spatial' )
    {
        $entropy_func = 'spatial_entropy';
    }
    elseif ( $match['pattern'] === 'dictionary' )
    {
        $entropy_func = 'dictionary_entropy';
    };

    $match['entropy'] = call_user_func( $entropy_func, $match );

    return $match['entropy'];
};

function repeat_entropy( $match )
{
    $cardinality = calc_bruteforce_cardinality( $match['token'] );

    return lg( $cardinality * strlen( $match['token'] ) );
};


function sequence_entropy( $match )
{
    $first_chr = $match['token'][0];

    if ( in_array( $first_chr, array( 'a', '1' ) ) )
    {
        $base_entropy = 1;
    }
    else
    {
        $ord = ord( $first_chr );

        if ( is_digit( $ord ) )
        {
            $base_entropy = lg( 10 ); # digits
        }
        elseif ( is_alpha( $ord ) )
        {
            $base_entropy = lg( 26 ); # lower
        }
        else
        {
            $base_entropy = lg( 26 ) + 1; # extra bit for uppercase
        };
    };

    if ( ! isset( $match['ascending'] ) )
    {
        $base_entropy += 1; # extra bit for descending instead of ascending
    };

    return $base_entropy + lg( strlen( $match['token'] ) );
};


function digits_entropy( $match )
{
    return lg( pow( 10, strlen( $match['token'] ) ) );
};


$NUM_YEARS = 119; # years match against 1900 - 2019
$NUM_MONTHS = 12;
$NUM_DAYS = 31;

function year_entropy( $match )
{
    return lg( $NUM_YEARS );
};

function date_entropy( $match )
{
    if ( $match['year'] < 100 )
    {
        $entropy = lg( $NUM_DAYS * $NUM_MONTHS * 100 ); # two-digit year
    }
    else
    {
        $entropy = lg( $NUM_DAYS * $NUM_MONTHS * $NUM_YEARS ); # four-digit year
    };

    if ( $match['separator'] )
    {
        $entropy += 2; # add two bits for separator selection [/,-,.,etc]
    };

    return $entropy;
};

function spatial_entropy( $match )
{
    if ( in_array( $match['graph'], array( 'qwerty', 'dvorak' ) ) )
    {
        $s = $KEYBOARD_STARTING_POSITIONS;
        $d = $KEYBOARD_AVERAGE_DEGREE;
    }
    else
    {
        $s = $KEYPAD_STARTING_POSITIONS;
        $d = $KEYPAD_AVERAGE_DEGREE;
    };

    $possibilities = 0;

    $L = strlen( $match['token'] );
    $t = $match['turns'];

    # estimate the number of possible patterns w/ length L or less with t turns or less.
    foreach ( range( 2, L + 1 ) as $i )
    {
        $possible_turns = min( $t, $i - 1 );

        foreach ( range( 1, $possible_turns + 1 ) as $j )
        {
            $x =  binom( $i - 1, $j - 1 ) * $s * pow( $d, $j );

            $possibilities += $x;
        };
    };

    $entropy = lg( $possibilities );

    # add extra entropy for shifted keys. (% instead of 5, A instead of a.)
    # math is similar to extra entropy from uppercase letters in dictionary matches.
    if ( isset( $match['shifted_count'] ) )
    {
        $S = $match['shifted_count'];
        $U = $L - $S; # unshifted count

        foreach ( range( 0, min( $S, $U ) ) as $i )
        {
            $possibilities += binom( $S + $U, $i );
        };

        $entropy += lg( $possibilities );
    };

    return $entropy;
};


function dictionary_entropy( $match )
{
    $match['base_entropy'] = lg( $match['rank'] ); # keep these as properties for display purposes
    $match['uppercase_entropy'] = extra_uppercase_entropy( $match );
    $match['l33t_entropy'] = extra_l33t_entropy( $match );
    return $match['base_entropy'] + $match['uppercase_entropy'] + $match['l33t_entropy'];
};

$START_UPPER = '/^[A-Z][^A-Z]+$/';
$END_UPPER = '/^[^A-Z]+[A-Z]$/';
$ALL_UPPER = '/^[A-Z]+$/';

function extra_uppercase_entropy( $match )
{
    global $START_UPPER, $END_UPPER, $ALL_UPPER;

    $word = $match['token'];

    if ( $word === strtolower( $word ) )
    {
        return 0;
    };

    # a capitalized word is the most common capitalization scheme,
    # so it only doubles the search space (uncapitalized + capitalized): 1 extra bit of entropy.
    # allcaps and end-capitalized are common enough too, underestimate as 1 extra bit to be safe.
    foreach ( array( $START_UPPER, $END_UPPER, $ALL_UPPER ) as $regex )
    {
        if ( preg_match( $regex, $word ) )
        {
            return 1;
        };
    };

    # Otherwise calculate the number of ways to capitalize U+L uppercase+lowercase letters with U uppercase letters or
    # less. Or, if there's more uppercase than lower (for e.g. PASSwORD), the number of ways to lowercase U+L letters
    # with L lowercase letters or less.
    $upp_len = 0;
    $low_len = 0;

    foreach ( str_split( $word ) as $x )
    {
        $ord = ord( $x );

        if ( is_upper( $ord ) )
        {
            $upp_len += 1;
        };

        if ( is_lower( $ord ) )
        {
            $low_len += 1;
        };
    };

    $possibilities = 0;

    foreach ( range( 0, min( $upp_len, $low_len ) + 1 ) as $i )
    {
        $possibilities += binom( $upp_len + $low_len,  $i );
    };

    return lg( $possibilities );
};


function extra_l33t_entropy( $match )
{
    if ( ! isset( $match['l33t'] ) )
    {
        return 0;
    };

    $possibilities = 0;

    foreach ( $match['sub'] as $subbed => $unsubbed )
    {
        $sub_len = 0;
        $unsub_len = 0;

        foreach ( $match['token'] as $x )
        {
            if ( $x === $subbed )
            {
                $sub_len += strlen( $x );
            };

            if ( $x === $unsubbed )
            {
                $unsub_len += strlen( $x );
            };
        };

        foreach ( range( 0, min( $unsub_len, $sub_len ) + 1 ) as $i )
        {
            $possibilities += binom( $unsub_len + $sub_len ) + $i;
        };
    };

    # corner: return 1 bit for single-letter subs, like 4pple -> apple, instead of 0.
    if ( $possibilities <= 1 )
    {
        return 1;
    };

    return lg( $possibilities );
};

# utilities --------------------------------------------------------------------

function is_lower( $ord )
{
    return ( $ord >= 0x61 && $ord <= 0x7a );
};

function is_digit( $ord )
{
    return ( $ord >= 0x30 && $ord <= 0x39 );
};

function is_upper( $ord )
{
    return ( $ord >= 0x41 && $ord <= 0x5a );
};

function is_alpha( $ord )
{
    return ( is_upper( $ord ) || is_lower( $ord ) );
};

function calc_bruteforce_cardinality( $password )
{
    $lower = 0;
    $upper = 0;
    $digits = 0;
    $symbols = 0;
    $unicode = 0;

    $password_chars = str_split( $password );

    foreach ( $password_chars as $char )
    {
        $ord = ord( $char );

        if ( is_digit( $ord ) )
        {
            $digits = 10;
        }
        elseif ( is_upper( $ord ) )
        {
            $upper = 26;
        }
        elseif ( is_lower( $ord ) )
        {
            $lower = 26;
        }
        elseif ( $ord <= 0x7f )
        {
            $symbols = 33;
        }
        else
        {
            $unicode = 100;
        };
    };

    $cardinality = $lower + $digits + $upper + $symbols + $unicode;

    return $cardinality;
}

function display_time( $seconds )
{
    $minute = 60;
    $hour = ( $minute * 60 );
    $day = ( $hour * 24 );
    $month = ( $day * 31 );
    $year = ( $month * 12 );
    $century = ( $year * 100 );

    if ( $seconds < $minute )
    {
        return 'instant';
    }
    elseif ( $seconds < $hour  )
    {
        return ( 1 + ceil( $seconds / $minute ) ) + ' minutes';
    }
    elseif ( $seconds < $day )
    {
        return ( 1 + ceil( $seconds / $hour ) ) + ' hours';
    }
    elseif ( $seconds < $month )
    {
        return ( 1 + ceil( $seconds / $day ) ) + ' days';
    }
    elseif ( $seconds < $year )
    {
        return ( 1 + ceil( $seconds / $month ) ) + ' months';
    }
    elseif ( $seconds < $century )
    {
        return ( 1 + ceil( $seconds / $year ) ) + ' years';
    }
    else
    {
        return 'centuries';
    };
};
?>